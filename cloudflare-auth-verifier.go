// Package cloudflareaccess dedicated package.
package cloudflareaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

// Config the plugin configuration.
type Config struct {
	teamName          string
	clientID          string
	skipClientIDCheck bool
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() Config {
	return Config{
		teamName:          "test",
		clientID:          "",
		skipClientIDCheck: false,
	}
}

// CloudflareAccess plugin.
type CloudflareAccess struct {
	Name     string
	Verifier *oidc.IDTokenVerifier
}

func main() {
	var config Config
	err := json.Unmarshal(handler.Host.GetConfig(), &config)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could not load config %v", err))
		os.Exit(1)
	}

	cloudflareAccess, err := New(config)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could not load config %v", err))
		os.Exit(1)
	}
	handler.HandleRequestFn = cloudflareAccess.HandleRequest
}

// New created a new plugin.
func New(config Config) (*CloudflareAccess, error) {
	// Add config checks
	teamDomain := fmt.Sprintf("https://%s.cloudflareaccess.com", config.teamName)
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", teamDomain)

	oidcConfig := &oidc.Config{
		ClientID:          config.clientID,
		SkipClientIDCheck: config.skipClientIDCheck,
	}
	keySet := oidc.NewRemoteKeySet(context.TODO(), certsURL)
	verifier := oidc.NewVerifier(teamDomain, keySet, oidcConfig)

	return &CloudflareAccess{
		Verifier: verifier,
	}, nil
}

// Implementation using "github.com/http-wasm/http-wasm-guest-tinygo" of ABI https://http-wasm.io/http-handler-abi/
func (e *CloudflareAccess) HandleRequest(req api.Request, resp api.Response) (next bool, reqCtx uint32) {
	headers := req.Headers()

	// Read from Header or Cookie
	accessJWT, found := headers.Get("Cf-Access-Jwt-Assertion")
	//if !found {
	// Handle token retrieval from Cookie
	//}

	if !found {
		resp.SetStatusCode(http.StatusUnauthorized)
		resp.Body().WriteString("No token on the request")
		return
	}

	// Verify the access token
	_, err := e.Verifier.Verify(context.TODO(), accessJWT)
	if err != nil {
		resp.SetStatusCode(http.StatusUnauthorized)
		resp.Body().WriteString(fmt.Sprintf("Invalid token: %s", err.Error()))
		return
	}
	return true, 0
}
