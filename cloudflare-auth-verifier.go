// Package cloudflareaccess dedicated package.
package cloudflareaccess

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Config the plugin configuration.
type Config struct {
	teamName          string
	clientID          string
	skipClientIDCheck bool
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		teamName:          "test",
		clientID:          "",
		skipClientIDCheck: false,
	}
}

// CloudflareAccess plugin.
type CloudflareAccess struct {
	Next     http.Handler
	Name     string
	Verifier *oidc.IDTokenVerifier
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Add config checks
	teamDomain := fmt.Sprintf("https://%s.cloudflareaccess.com", config.teamName)
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", teamDomain)

	oidcConfig := &oidc.Config{
		ClientID:          config.clientID,
		SkipClientIDCheck: config.skipClientIDCheck,
	}
	keySet := oidc.NewRemoteKeySet(ctx, certsURL)
	verifier := oidc.NewVerifier(teamDomain, keySet, oidcConfig)

	return &CloudflareAccess{
		Next:     next,
		Name:     name,
		Verifier: verifier,
	}, nil
}

func (e *CloudflareAccess) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	headers := req.Header

	// Read from Header or Cookie
	accessJWT := headers.Get("Cf-Access-Jwt-Assertion")
	if accessJWT == "" {
		cookie, err := req.Cookie("CF_AUTHORIZATION")
		if err == nil {
			accessJWT = cookie.Value
		}
	}

	if accessJWT == "" {
		rw.WriteHeader(http.StatusUnauthorized)
		_, err := rw.Write([]byte("No token on the request"))
		if err != nil {
			return
		}
		return
	}

	// Verify the access token
	ctx := req.Context()
	_, err := e.Verifier.Verify(ctx, accessJWT)
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		_, e := rw.Write([]byte(fmt.Sprintf("Invalid token: %s", err.Error())))
		if e != nil {
			return
		}
		return
	}
	e.Next.ServeHTTP(rw, req)
}
