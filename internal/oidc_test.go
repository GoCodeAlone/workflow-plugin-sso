package internal

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// --- Mock OIDC server ---

type mockOIDCServer struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	issuer   string
	clientID string
}

func newMockOIDCServer(t *testing.T, clientID string) *mockOIDCServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	m := &mockOIDCServer{key: key, clientID: clientID}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/keys", m.handleJWKS)
	mux.HandleFunc("/userinfo", m.handleUserInfo)
	mux.HandleFunc("/token", m.handleToken)

	m.server = httptest.NewServer(mux)
	m.issuer = m.server.URL
	return m
}

func (m *mockOIDCServer) close() {
	m.server.Close()
}

func (m *mockOIDCServer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                 m.issuer,
		"authorization_endpoint": m.issuer + "/authorize",
		"token_endpoint":         m.issuer + "/token",
		"userinfo_endpoint":      m.issuer + "/userinfo",
		"jwks_uri":               m.issuer + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (m *mockOIDCServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(m.key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.key.PublicKey.E)).Bytes())
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": "test-key-1",
				"n":   n,
				"e":   e,
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (m *mockOIDCServer) handleUserInfo(w http.ResponseWriter, _ *http.Request) {
	info := map[string]any{
		"sub":     "user-123",
		"email":   "test@example.com",
		"name":    "Test User",
		"profile": "https://example.com/test",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (m *mockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	token := m.createTestJWT(map[string]any{
		"sub":    "user-123",
		"email":  "test@example.com",
		"name":   "Test User",
		"roles":  []string{"admin", "user"},
		"groups": []string{"engineering"},
	}, time.Now().Add(time.Hour))

	resp := map[string]any{
		"access_token":  "mock-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "mock-refresh-token",
		"id_token":      token,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockOIDCServer) createTestJWT(claims map[string]any, expiry time.Time) string {
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "test-key-1",
	}

	claims["iss"] = m.issuer
	claims["aud"] = m.clientID
	claims["iat"] = time.Now().Unix()
	claims["exp"] = expiry.Unix()

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64

	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, h[:])
	if err != nil {
		panic(fmt.Sprintf("sign JWT: %v", err))
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64
}

// --- Helper to set up a provider from the mock server ---

func setupTestProvider(t *testing.T, mock *mockOIDCServer) *OIDCProvider {
	t.Helper()
	ctx := context.Background()
	cfg := ProviderConfig{
		Name:     "test-provider",
		Type:     "generic",
		Issuer:   mock.issuer,
		ClientID: mock.clientID,
		ClaimMapping: ClaimMapping{
			Roles:  "roles",
			Groups: "groups",
			Email:  "email",
			Name:   "name",
		},
	}
	p, err := InitProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("InitProvider: %v", err)
	}
	return p
}

// --- Tests ---

func TestProviderRegistry(t *testing.T) {
	reg := NewProviderRegistry()

	p1 := &OIDCProvider{ProviderName: "p1", Issuer: "https://issuer1.example.com"}
	p2 := &OIDCProvider{ProviderName: "p2", Issuer: "https://issuer2.example.com"}

	reg.Register(p1)
	reg.Register(p2)

	got, ok := reg.Get("p1")
	if !ok || got.ProviderName != "p1" {
		t.Error("expected to find p1")
	}

	got, ok = reg.FindByIssuer("https://issuer2.example.com")
	if !ok || got.ProviderName != "p2" {
		t.Error("expected to find p2 by issuer")
	}

	_, ok = reg.FindByIssuer("https://unknown.example.com")
	if ok {
		t.Error("expected not to find unknown issuer")
	}

	all := reg.All()
	if len(all) != 2 {
		t.Errorf("expected 2 providers, got %d", len(all))
	}

	reg.Remove("p1")
	_, ok = reg.Get("p1")
	if ok {
		t.Error("expected p1 to be removed")
	}
}

func TestExtractClaims(t *testing.T) {
	claims := map[string]any{
		"email": "user@example.com",
		"name":  "John Doe",
		"roles": []any{"admin", "editor"},
		"realm_access": map[string]any{
			"roles": []any{"realm_admin"},
		},
		"groups": []any{"eng", "platform"},
	}

	// Standard paths
	email, name, roles, groups := ExtractClaims(claims, ClaimMapping{
		Email:  "email",
		Name:   "name",
		Roles:  "roles",
		Groups: "groups",
	})
	if email != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", email)
	}
	if name != "John Doe" {
		t.Errorf("name = %q, want John Doe", name)
	}
	if len(roles) != 2 || roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin editor]", roles)
	}
	if len(groups) != 2 {
		t.Errorf("groups = %v, want [eng platform]", groups)
	}

	// Nested path (Keycloak-style)
	_, _, nestedRoles, _ := ExtractClaims(claims, ClaimMapping{
		Roles: "realm_access.roles",
	})
	if len(nestedRoles) != 1 || nestedRoles[0] != "realm_admin" {
		t.Errorf("nested roles = %v, want [realm_admin]", nestedRoles)
	}
}

func TestDecodeUnverifiedIssuer(t *testing.T) {
	// Create a simple JWT with known iss
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://example.com","sub":"user1"}`))
	token := "eyJhbGciOiJSUzI1NiJ9." + payload + ".fakesignature"

	iss, err := DecodeUnverifiedIssuer(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if iss != "https://example.com" {
		t.Errorf("iss = %q, want https://example.com", iss)
	}

	// Invalid JWT
	_, err = DecodeUnverifiedIssuer("not-a-jwt")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestValidateTokenStep_WithMockServer(t *testing.T) {
	mock := newMockOIDCServer(t, "test-client")
	defer mock.close()

	registry := NewProviderRegistry()
	p := setupTestProvider(t, mock)
	registry.Register(p)

	step := newValidateTokenStep("test", nil, registry)

	// Create a valid token
	token := mock.createTestJWT(map[string]any{
		"sub":    "user-123",
		"email":  "user@example.com",
		"name":   "Test User",
		"roles":  []string{"admin"},
		"groups": []string{"engineering"},
	}, time.Now().Add(time.Hour))

	ctx := context.Background()
	result, err := step.Execute(ctx, nil, nil, map[string]any{
		"token": token,
	}, nil, nil)

	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["valid"] != true {
		t.Errorf("expected valid=true, got %v (error: %v)", result.Output["valid"], result.Output["error"])
	}
	if result.Output["userId"] != "user-123" {
		t.Errorf("userId = %v, want user-123", result.Output["userId"])
	}
	if result.Output["email"] != "user@example.com" {
		t.Errorf("email = %v, want user@example.com", result.Output["email"])
	}
	if result.Output["provider"] != "test-provider" {
		t.Errorf("provider = %v, want test-provider", result.Output["provider"])
	}
}

func TestValidateTokenStep_NoToken(t *testing.T) {
	registry := NewProviderRegistry()
	step := newValidateTokenStep("test", nil, registry)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, map[string]any{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["valid"] != false {
		t.Errorf("expected valid=false for missing token")
	}
}

func TestValidateTokenStep_InvalidToken(t *testing.T) {
	mock := newMockOIDCServer(t, "test-client")
	defer mock.close()

	registry := NewProviderRegistry()
	p := setupTestProvider(t, mock)
	registry.Register(p)

	step := newValidateTokenStep("test", nil, registry)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"token":    "invalid.jwt.token",
		"provider": "test-provider",
	}, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["valid"] != false {
		t.Errorf("expected valid=false for invalid token")
	}
}

func TestValidateTokenStep_BearerPrefix(t *testing.T) {
	mock := newMockOIDCServer(t, "test-client")
	defer mock.close()

	registry := NewProviderRegistry()
	p := setupTestProvider(t, mock)
	registry.Register(p)

	step := newValidateTokenStep("test", nil, registry)

	token := mock.createTestJWT(map[string]any{
		"sub":   "user-456",
		"email": "bearer@example.com",
		"name":  "Bearer User",
	}, time.Now().Add(time.Hour))

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"authorization": "Bearer " + token,
	}, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["valid"] != true {
		t.Errorf("expected valid=true with Bearer prefix, got error: %v", result.Output["error"])
	}
}

func TestValidateTokenStep_ExpiredToken(t *testing.T) {
	mock := newMockOIDCServer(t, "test-client")
	defer mock.close()

	registry := NewProviderRegistry()
	p := setupTestProvider(t, mock)
	registry.Register(p)

	step := newValidateTokenStep("test", nil, registry)

	token := mock.createTestJWT(map[string]any{
		"sub": "user-expired",
	}, time.Now().Add(-time.Hour)) // expired

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"token":    token,
		"provider": "test-provider",
	}, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["valid"] != false {
		t.Errorf("expected valid=false for expired token")
	}
}

func TestUserInfoStep(t *testing.T) {
	mock := newMockOIDCServer(t, "test-client")
	defer mock.close()

	registry := NewProviderRegistry()
	p := setupTestProvider(t, mock)
	registry.Register(p)

	step := newUserInfoStep("test", nil, registry)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider":    "test-provider",
		"accessToken": "mock-access-token",
	}, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["sub"] != "user-123" {
		t.Errorf("sub = %v, want user-123", result.Output["sub"])
	}
	if result.Output["email"] != "test@example.com" {
		t.Errorf("email = %v, want test@example.com", result.Output["email"])
	}
}

func TestEntraIssuer(t *testing.T) {
	got := EntraIssuer("my-tenant-id")
	want := "https://login.microsoftonline.com/my-tenant-id/v2.0"
	if got != want {
		t.Errorf("EntraIssuer = %q, want %q", got, want)
	}

	if EntraIssuer("") != "" {
		t.Error("expected empty for empty tenant")
	}
}

func TestOktaIssuer(t *testing.T) {
	got := OktaIssuer("dev-12345.okta.com", "aus123")
	want := "https://dev-12345.okta.com/oauth2/aus123"
	if got != want {
		t.Errorf("OktaIssuer = %q, want %q", got, want)
	}

	// Default auth server
	got = OktaIssuer("dev-12345.okta.com", "")
	want = "https://dev-12345.okta.com/oauth2/default"
	if got != want {
		t.Errorf("OktaIssuer default = %q, want %q", got, want)
	}

	if OktaIssuer("", "") != "" {
		t.Error("expected empty for empty domain")
	}
}

func TestInitProvider_WithMockServer(t *testing.T) {
	mock := newMockOIDCServer(t, "test-client")
	defer mock.close()

	p := setupTestProvider(t, mock)
	if p.ProviderName != "test-provider" {
		t.Errorf("name = %q, want test-provider", p.ProviderName)
	}
	if p.Issuer != mock.issuer {
		t.Errorf("issuer = %q, want %q", p.Issuer, mock.issuer)
	}
	if p.Verifier == nil {
		t.Error("verifier is nil")
	}
	if p.OAuthCfg == nil {
		t.Error("oauth config is nil")
	}
}

func TestOIDCModule_Init(t *testing.T) {
	mock := newMockOIDCServer(t, "test-client")
	defer mock.close()

	registry := NewProviderRegistry()
	mod := newOIDCModule("test-mod", map[string]any{
		"providers": []any{
			map[string]any{
				"name":     "mock",
				"type":     "generic",
				"issuer":   mock.issuer,
				"clientId": "test-client",
			},
		},
	}, registry)

	if err := mod.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	p, ok := registry.Get("mock")
	if !ok {
		t.Fatal("expected provider 'mock' to be registered")
	}
	if p.Issuer != mock.issuer {
		t.Errorf("issuer = %q, want %q", p.Issuer, mock.issuer)
	}
}

func TestOIDCModule_Stop(t *testing.T) {
	mock := newMockOIDCServer(t, "test-client")
	defer mock.close()

	registry := NewProviderRegistry()
	mod := newOIDCModule("test-mod", map[string]any{
		"providers": []any{
			map[string]any{
				"name":     "mock",
				"type":     "generic",
				"issuer":   mock.issuer,
				"clientId": "test-client",
			},
		},
	}, registry)

	if err := mod.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := mod.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	_, ok := registry.Get("mock")
	if ok {
		t.Error("expected provider to be removed after Stop")
	}
}

// Suppress unused import warnings
var (
	_ = oidc.ScopeOpenID
	_ = oauth2.StaticTokenSource
)

