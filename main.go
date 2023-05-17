package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// UserInfo hold infromation fetch using Auth0 resource endpoint
type UserInfo struct {
	Sub           string    `json:"sub"`
	GivenName     string    `json:"given_name"`
	FamilyName    string    `json:"family_name"`
	Nickname      string    `json:"nickname"`
	Name          string    `json:"name"`
	Picture       string    `json:"picture"`
	Locale        string    `json:"locale"`
	UpdatedAt     time.Time `json:"updated_at"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
}

// Server represents the HTTP server.
type Server struct {
	router       *gin.Engine    // Gin router instance
	oauth2config *oauth2.Config // OAuth2 configuration
}

// NewOauth2Config creates a new OAuth2 configuration.
// It retrieves the necessary environment variables and initializes the configuration.
func NewOauth2Config() (*oauth2.Config, error) {
	// Create a new OpenID Connect provider using the AUTH0_DOMAIN environment variable.
	provider, err := oidc.NewProvider(
		context.Background(),
		"https://"+os.Getenv("AUTH0_DOMAIN")+"/",
	)
	if err != nil {
		return nil, fmt.Errorf("could not create new provider: %v", err)
	}

	// Initialize the OAuth2 configuration using the environment variables.
	oauthConfig := &oauth2.Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AUTH0_CALLBACK_URL"),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "picture"},
		Endpoint:     provider.Endpoint(),
	}

	return oauthConfig, nil
}

// NewServer creates a new instance of Server.
func NewServer() (*Server, error) {
	router := gin.New()

	oauth2Config, err := NewOauth2Config()
	if err != nil {
		return nil, fmt.Errorf("could not create new oauth config: %v", err)
	}

	server := &Server{
		router:       router,
		oauth2config: oauth2Config,
	}

	return server, nil
}

// loginHandler handles the login route.
func (s *Server) loginHandler(ctx *gin.Context) {
	state, err := generateRandomString()
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
		return
	}

	// Save state value in session storage
	session := sessions.Default(ctx)
	session.Set("state", state)

	if err := session.Save(); err != nil {
		ctx.JSON(http.StatusInternalServerError, "could not login")
		return
	}

	ctx.Redirect(http.StatusTemporaryRedirect, s.oauth2config.AuthCodeURL(state))
}

// logoutHandler
func (s *Server) logoutHandler(ctx *gin.Context) {
	// delete all the cookies and session values
	// Set cookie timestamp as negative
	ctx.SetCookie("at", "", -1, "/", "", false, true)
	ctx.SetCookie("u", "", -1, "/", "", false, true)
	ctx.SetCookie("auth-sessions", "", -1, "/", "", false, true)

	// Call auth0 logout endpoint to clear session and tokens from auth0 side
	logoutURL, err := url.Parse("https://" + os.Getenv("AUTH0_DOMAIN") + "/v2/logout")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, "could not logout")
		return
	}

	// Check if request was performed via http or https
	scheme := "http"
	if ctx.Request.TLS != nil {
		scheme = "https"
	}

	// redirecting user back to homepage
	redirectionURL, err := url.Parse(scheme + "://" + ctx.Request.Host)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, "could not parse URL")
		return
	}

	// add url params
	parameters := url.Values{}
	parameters.Add("returnTo", redirectionURL.String())
	parameters.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	logoutURL.RawQuery = parameters.Encode()

	ctx.Redirect(http.StatusTemporaryRedirect, logoutURL.String())
}

// callbackHandler handles the callback route.
func (s *Server) callbackHandler(ctx *gin.Context) {

	// Checking if state param passed from callback matches what's stored in
	// memory
	session := sessions.Default(ctx)
	if session.Get("state") != ctx.Query("state") {
		ctx.JSON(http.StatusInternalServerError, "invalid state param")
		return
	}

	// get authorization code
	code := ctx.Query("code")
	token, err := s.oauth2config.Exchange(ctx, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, "could not exchange oauth code")
		return
	}

	if !token.Valid() {
		ctx.JSON(http.StatusInternalServerError, "invalid access token")
		return
	}

	// get user information to display in profile
	client := s.oauth2config.Client(ctx, token)
	resp, err := client.Get("https://" + os.Getenv("AUTH0_DOMAIN") + "/userinfo")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, "could not fetch user information")
		return
	}

	// parse response body
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, "could not parse response body")
	}

	// TODO: cookie should be encrypted before storing.
	// save access token and response body in cookie
	// u => userInfo
	ctx.SetCookie("u", string(b), int(time.Now().Add(1*time.Hour).Unix()), "/", "localhost", true, true)
	// at => accessToken
	ctx.SetCookie("at", token.AccessToken, int(time.Now().Add(1*time.Hour).Unix()), "/", "localhost", true, true)

	ctx.Redirect(http.StatusTemporaryRedirect, "/profile")
}

func main() {
	server, err := NewServer()
	if err != nil {
		log.Fatalf("could not create new server: %v", err)
	}

	// Define session storage
	// TODO: pass this secret from env variable
	store := cookie.NewStore([]byte("superSecretValue"))
	server.router.Use(sessions.Sessions("auth-sessions", store))

	server.router.Static("/public", "web/static")
	server.router.LoadHTMLGlob("web/template/*")

	server.router.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, "pong")
	})

	server.router.GET("/", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "home.html", nil)
	})

	server.router.GET("/profile", IsAuthenticated(), func(ctx *gin.Context) {
		// Show user information in profile

		userInfo, err := ctx.Cookie("u")
		if err != nil {
			// if user info cookie does not exists, then we redirect user back to home page
			ctx.Redirect(http.StatusTemporaryRedirect, "/")
			return
		}

		var u UserInfo
		if err := json.Unmarshal([]byte(userInfo), &u); err != nil {
			ctx.JSON(http.StatusInternalServerError, "something wrong. Please try logging in again")
		}

		ctx.HTML(http.StatusOK, "profile.html", gin.H{
			"Profile": u,
		})
	})

	server.router.GET("/login", server.loginHandler)
	server.router.GET("/logout", server.logoutHandler)

	server.router.GET("/callback", server.callbackHandler)

	if err := server.router.Run(":9090"); err != nil {
		log.Fatalf("could not run server: %v", err)
	}
}

// Implement authenticaton middleware to make sure user is authenticated before taking to
// protected endpoint
func IsAuthenticated() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		accessToken, err := ctx.Cookie("at")
		if err != nil {
			// Cookie does not exists, hence abort and redirect user to home page or login page
			ctx.Redirect(http.StatusTemporaryRedirect, "/")
			ctx.Abort()
			return
		}

		// Check if token is empty
		if accessToken == "" {
			// Cookie does not exists, hence abort and redirect user to home page or login page
			ctx.Redirect(http.StatusTemporaryRedirect, "/")
			ctx.Abort()
			return
		}

		// If everything is okay, forward the request to the handler
		ctx.Next()
	}
}

func generateRandomString() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.StdEncoding.EncodeToString(b)

	return state, nil
}
