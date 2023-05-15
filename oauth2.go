package main

import (
	"context"
	"os"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

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
		Scopes:       []string{"profile", "email", "photo"},
		Endpoint:     provider.Endpoint(),
	}

	return oauthConfig, nil
}
