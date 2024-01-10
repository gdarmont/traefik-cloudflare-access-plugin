package cloudflareaccess_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/gdarmont/go-jose/v3"
	"github.com/gdarmont/go-oidc/v3/oidc"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gdarmont/traefik-cloudflare-access-plugin"
)

func TestCloudflareAccessMissingHeader(t *testing.T) {
	// Given
	cfg := cloudflareaccess.CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := cloudflareaccess.New(ctx, next, cfg, "cloudflare-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusUnauthorized)
}

func TestCloudflareAccessValidCookieToken(t *testing.T) {
	// Given
	// Preparing a new Token
	test := verificationTest{
		issuer:  "https://testdomain",
		name:    "default signing alg",
		idToken: `{"iss":"https://testdomain","claim1": "abc"}`,
		config: oidc.Config{
			SkipClientIDCheck: true,
			SkipExpiryCheck:   true,
		},
		signKey: newRSAKey(t),
	}

	// Creating a signed token
	token := test.signKey.sign(t, []byte(test.idToken))

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	// Creating the plugin
	handler := cloudflareaccess.CloudflareAccess{
		Next: next,
		Name: "cloudflare-plugin",
		Verifier: oidc.NewVerifier(
			test.issuer,
			&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{test.signKey.pub}},
			&test.config),
	}

	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	req.AddCookie(&http.Cookie{Name: "CF_AUTHORIZATION", Value: token})
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestCloudflareAccessValidHeaderToken(t *testing.T) {
	// Given
	// Preparing a new Token
	test := verificationTest{
		issuer:  "https://testdomain",
		name:    "default signing alg",
		idToken: `{"iss":"https://testdomain","claim1": "abc"}`,
		config: oidc.Config{
			SkipClientIDCheck: true,
			SkipExpiryCheck:   true,
		},
		signKey: newRSAKey(t),
	}

	// Creating a signed token
	token := test.signKey.sign(t, []byte(test.idToken))

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	// Creating the plugin
	handler := cloudflareaccess.CloudflareAccess{
		Next: next,
		Name: "cloudflare-plugin",
		Verifier: oidc.NewVerifier(
			test.issuer,
			&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{test.signKey.pub}},
			&test.config),
	}

	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	req.Header.Add("Cf-Access-Jwt-Assertion", token)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusOK)
}

func TestCloudflareAccessInvalidIssuerToken(t *testing.T) {
	// Given
	// Preparing a new Token
	test := verificationTest{
		issuer: "https://testdomain",
		name:   "default signing alg",
		// Setting iss to a different issuer
		idToken: `{"iss":"https://testdomain.com","claim1": "abc"}`,
		config: oidc.Config{
			SkipClientIDCheck: true,
			SkipExpiryCheck:   true,
		},
		signKey: newRSAKey(t),
	}

	// Creating a signed token
	token := test.signKey.sign(t, []byte(test.idToken))

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	// Creating the plugin
	handler := cloudflareaccess.CloudflareAccess{
		Next: next,
		Name: "cloudflare-plugin",
		Verifier: oidc.NewVerifier(
			test.issuer,
			&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{test.signKey.pub}},
			&test.config),
	}

	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	req.Header.Add("Cf-Access-Jwt-Assertion", token)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusUnauthorized)
}

func TestCloudflareAccessInvalidKeyToken(t *testing.T) {
	// Given
	// Preparing a new Token
	test := verificationTest{
		issuer:  "https://testdomain",
		name:    "default signing alg",
		idToken: `{"iss":"https://testdomain","claim1": "abc"}`,
		config: oidc.Config{
			SkipClientIDCheck: true,
			SkipExpiryCheck:   true,
		},
		signKey: newRSAKey(t),
	}

	// Creating a signed token
	token := test.signKey.sign(t, []byte(test.idToken))

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	// Creating the plugin
	handler := cloudflareaccess.CloudflareAccess{
		Next: next,
		Name: "cloudflare-plugin",
		Verifier: oidc.NewVerifier(
			test.issuer,
			&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{newRSAKey(t).pub}},
			&test.config),
	}

	recorder := httptest.NewRecorder()

	// When
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	req.Header.Add("Cf-Access-Jwt-Assertion", token)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	// Then
	assertStatusCode(t, recorder.Result(), http.StatusUnauthorized)
}

func assertStatusCode(t *testing.T, req *http.Response, expected int) {
	t.Helper()

	if req.StatusCode != expected {
		t.Errorf("invalid status code value: %d, expected %d", req.StatusCode, expected)
	}
}

// Extracted from oidc/verify_test.go
type signingKey struct {
	keyID string // optional
	priv  interface{}
	pub   interface{}
	alg   jose.SignatureAlgorithm
}

func newRSAKey(t testing.TB) *signingKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", priv, priv.Public(), jose.RS256}
}

type verificationTest struct {
	// Name of the subtest.
	name string

	// If not provided defaults to "https://foo"
	issuer string

	// JWT payload (just the claims).
	idToken string

	// Key to sign the ID Token with.
	signKey *signingKey
	// If not provided defaults to signKey. Only useful when
	// testing invalid signatures.
	verificationKey *signingKey

	config        oidc.Config
	wantErr       bool
	wantErrExpiry bool
}

func (s *signingKey) sign(t testing.TB, payload []byte) string {
	privKey := &jose.JSONWebKey{Key: s.priv, Algorithm: string(s.alg), KeyID: s.keyID}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
