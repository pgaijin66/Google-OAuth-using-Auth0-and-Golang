package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

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
	ctx.Redirect(http.StatusTemporaryRedirect, s.oauth2config.AuthCodeURL(state))
}

// callbackHandler handles the callback route.
func (s *Server) callbackHandler(ctx *gin.Context) {
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

	ctx.Redirect(http.StatusTemporaryRedirect, "/profile")
}
