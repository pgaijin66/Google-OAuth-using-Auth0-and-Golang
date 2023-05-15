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

type Profile struct {
	Sub           string `json:"sub"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Nickname      string `json:"nickname"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
	UpdatedAt     string `json:"updated_at"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// Server represents the HTTP server.
type Server struct {
	router       *gin.Engine    // Gin router instance
	oauth2config *oauth2.Config // OAuth2 configuration
}

// NewServer creates a new instance of Server.
func NewServer() (*Server, error) {
	router := gin.New()

	oauth2Config, err := NewOauth2Config()
	if err != nil {
		return nil, fmt.Errorf("could not create new oauth config: %v", err)
	}

	return &Server{
		router:       router,
		oauth2config: oauth2Config,
	}, nil
}

// Run starts the server.
func (s *Server) Run() error {
	if err := s.router.Run(":9090"); err != nil {
		return fmt.Errorf("could not start server: %v", err)
	}
	return nil
}

// loginHandler handles the login route.
func (s *Server) loginHandler(ctx *gin.Context) {
	state, err := generateRandomString()
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
		return
	}

	session := sessions.Default(ctx)
	session.Set("state", state)
	if err := session.Save(); err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
		return
	}

	ctx.Redirect(http.StatusTemporaryRedirect, s.oauth2config.AuthCodeURL(state))
}

// callbackHandler handles the callback route.
func (s *Server) callbackHandler(ctx *gin.Context) {
	session := sessions.Default(ctx)
	if ctx.Query("state") != session.Get("state") {
		ctx.String(http.StatusBadRequest, "Invalid state parameter.")
		return
	}

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

	client := s.oauth2config.Client(context.Background(), token)
	resp, err := client.Get("https://" + os.Getenv("AUTH0_DOMAIN") + "/userinfo")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, "invalid access token")
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	ctx.SetCookie("access_token", token.AccessToken, int(time.Now().Add(1*time.Hour).Unix()), "/", "localhost", true, false)
	ctx.SetCookie("profile", string(body), int(time.Now().Add(1*time.Hour).Unix()), "/", "localhost", true, false)

	ctx.Redirect(http.StatusTemporaryRedirect, "/profile")
}

// callbackHandler handles the callback route.
func (s *Server) logoutHandler(ctx *gin.Context) {

	ctx.SetCookie("access_token", "", int(time.Now().Add(-1*time.Hour).Unix()), "/", "", false, true)
	ctx.SetCookie("profile", "", int(time.Now().Add(-1*time.Hour).Unix()), "/", "", false, true)

	logoutUrl, err := url.Parse("https://" + os.Getenv("AUTH0_DOMAIN") + "/v2/logout")
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
		return
	}

	scheme := "http"
	if ctx.Request.TLS != nil {
		scheme = "https"
	}

	returnTo, err := url.Parse(scheme + "://" + ctx.Request.Host)
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
		return
	}

	parameters := url.Values{}
	parameters.Add("returnTo", returnTo.String())
	parameters.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	logoutUrl.RawQuery = parameters.Encode()

	ctx.Redirect(http.StatusTemporaryRedirect, logoutUrl.String())
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
		return nil, err
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

func generateRandomString() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.StdEncoding.EncodeToString(b)

	return state, nil
}

func main() {
	server, err := NewServer()
	if err != nil {
		log.Fatalf("could not create new server: %v", err)
	}

	store := cookie.NewStore([]byte("secret"))
	server.router.Use(sessions.Sessions("auth-session", store))

	server.router.Static("/public", "web/static")
	server.router.LoadHTMLGlob("web/template/*")

	server.router.GET("/", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "home.html", nil)
	})

	server.router.GET("/profile", IsAuthenticated(), func(ctx *gin.Context) {

		profile, err := ctx.Cookie("profile")
		if err != nil {
			ctx.Redirect(http.StatusTemporaryRedirect, "/")
			ctx.Abort()
			return
		}

		var p Profile
		if err := json.Unmarshal([]byte(profile), &p); err != nil {
			fmt.Println(err)
		}

		ctx.HTML(http.StatusOK, "profile.html", gin.H{
			"Profile": p,
		})
	})

	server.router.GET("/login", server.loginHandler)
	server.router.GET("/logout", server.logoutHandler)

	server.router.GET("/callback", server.callbackHandler)

	if err := server.Run(); err != nil {
		log.Fatalf("could not run server: %v", err)
	}
}

func IsAuthenticated() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		accessToken, err := ctx.Cookie("access_token")
		if err != nil {
			ctx.Redirect(http.StatusTemporaryRedirect, "/")
			ctx.Abort()
			return
		}

		if accessToken == "" {
			ctx.Redirect(http.StatusTemporaryRedirect, "/")
			ctx.Abort()
			return
		}
		ctx.Next()

	}
}
