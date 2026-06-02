package internal

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// TestInitProvider_JWKSUri_AcceptsValidToken verifies that InitProvider with a
// JWKSURI (no OIDC discovery) builds a provider whose Verifier accepts a valid
// RS256 token issued by the mock. SigningAlgorithms is set to ["RS256"] explicitly
// so the acceptance is deterministic (not accidental from any default).
func TestInitProvider_JWKSUri_AcceptsValidToken(t *testing.T) {
	mock := newMockOIDCServer(t, "app-b")
	defer mock.close()

	// Track discovery hits — there must be NONE in jwksUri mode.
	var discoveryHits atomic.Int32
	origHandler := mock.server.Config.Handler
	mock.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discoveryHits.Add(1)
		}
		origHandler.ServeHTTP(w, r)
	})

	ctx := context.Background()
	p, err := InitProvider(ctx, ProviderConfig{
		Name:              "app-a",
		Issuer:            mock.issuer,
		JWKSURI:           mock.issuer + "/keys",
		ClientID:          "app-b",
		SigningAlgorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("InitProvider with JWKSURI: %v", err)
	}
	if p == nil {
		t.Fatal("InitProvider returned nil provider")
	}
	if p.Verifier == nil {
		t.Fatal("provider has nil Verifier")
	}

	// No OIDC discovery should have been hit.
	if discoveryHits.Load() != 0 {
		t.Errorf("OIDC discovery endpoint hit %d time(s); jwksUri mode must skip discovery", discoveryHits.Load())
	}

	// Mint a valid token: iss=mock.issuer, aud=app-b.
	token := mock.createTestJWT(map[string]any{
		"sub":   "svc-caller",
		"email": "svc@example.com",
	}, time.Now().Add(time.Hour))

	idToken, err := p.Verifier.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verifier.Verify accepted token: unexpected error: %v", err)
	}
	if idToken == nil {
		t.Fatal("Verifier.Verify returned nil IDToken without error")
	}
}

// TestInitProvider_JWKSUri_RejectsDifferentKey verifies that a token signed by
// a DIFFERENT RSA key is rejected (wrong-key scenario).
func TestInitProvider_JWKSUri_RejectsDifferentKey(t *testing.T) {
	// mock is the "real" App A — its JWKS is registered in the provider.
	mock := newMockOIDCServer(t, "app-b")
	defer mock.close()

	// attacker is a separate server with its own key; we use it only to mint tokens.
	attacker := newMockOIDCServer(t, "app-b")
	defer attacker.close()
	// Override attacker's issuer claim to match mock's issuer so only the key differs.
	attacker.issuer = mock.issuer

	ctx := context.Background()
	p, err := InitProvider(ctx, ProviderConfig{
		Name:              "app-a",
		Issuer:            mock.issuer,
		JWKSURI:           mock.issuer + "/keys", // real App A JWKS
		ClientID:          "app-b",
		SigningAlgorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("InitProvider: %v", err)
	}

	// Token signed by attacker's key (different from the JWKS at mock.issuer+/keys).
	badToken := attacker.createTestJWT(map[string]any{
		"sub": "attacker",
	}, time.Now().Add(time.Hour))

	_, err = p.Verifier.Verify(ctx, badToken)
	if err == nil {
		t.Fatal("Verifier.Verify should have rejected token signed by a different key; got nil error")
	}
}

// TestInitProvider_JWKSUri_RejectsAudMismatch verifies that a token with the
// wrong audience is rejected.
func TestInitProvider_JWKSUri_RejectsAudMismatch(t *testing.T) {
	mock := newMockOIDCServer(t, "app-b")
	defer mock.close()

	ctx := context.Background()
	p, err := InitProvider(ctx, ProviderConfig{
		Name:              "app-a",
		Issuer:            mock.issuer,
		JWKSURI:           mock.issuer + "/keys",
		ClientID:          "app-b", // expect aud=app-b
		SigningAlgorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("InitProvider: %v", err)
	}

	// Mint a token with aud=wrong-client (overrides the mock server's default clientID).
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key-1"}
	claims := map[string]any{
		"sub": "svc",
		"iss": mock.issuer,
		"aud": "wrong-client", // mismatch
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	wrongAudToken := signTestJWT(t, mock.key, header, claims)

	_, err = p.Verifier.Verify(ctx, wrongAudToken)
	if err == nil {
		t.Fatal("Verifier.Verify should have rejected aud-mismatch token; got nil error")
	}
}

// TestInitProvider_JWKSUri_RejectsIssMismatch verifies that a token with the
// wrong issuer is rejected.
func TestInitProvider_JWKSUri_RejectsIssMismatch(t *testing.T) {
	mock := newMockOIDCServer(t, "app-b")
	defer mock.close()

	ctx := context.Background()
	p, err := InitProvider(ctx, ProviderConfig{
		Name:              "app-a",
		Issuer:            mock.issuer,
		JWKSURI:           mock.issuer + "/keys",
		ClientID:          "app-b",
		SigningAlgorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("InitProvider: %v", err)
	}

	// Mint a token with iss=http://evil — signed by mock's key (key is valid) but issuer wrong.
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key-1"}
	claims := map[string]any{
		"sub": "evil",
		"iss": "http://evil.example.com", // mismatch
		"aud": "app-b",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	wrongIssToken := signTestJWT(t, mock.key, header, claims)

	_, err = p.Verifier.Verify(ctx, wrongIssToken)
	if err == nil {
		t.Fatal("Verifier.Verify should have rejected iss-mismatch token; got nil error")
	}
}

// TestInitProvider_JWKSUri_DefaultAlgorithms verifies that when SigningAlgorithms
// is empty, the provider still initialises (ES256+RS256 defaulted internally)
// and does not require discovery.
func TestInitProvider_JWKSUri_DefaultAlgorithms(t *testing.T) {
	mock := newMockOIDCServer(t, "app-b")
	defer mock.close()

	ctx := context.Background()
	p, err := InitProvider(ctx, ProviderConfig{
		Name:     "app-a",
		Issuer:   mock.issuer,
		JWKSURI:  mock.issuer + "/keys",
		ClientID: "app-b",
		// SigningAlgorithms omitted → defaults to ["ES256","RS256"]
	})
	if err != nil {
		t.Fatalf("InitProvider with default algs: %v", err)
	}
	if p == nil || p.Verifier == nil {
		t.Fatal("expected non-nil provider and verifier with default algorithms")
	}

	// The default includes RS256, so a RS256 mock token should verify.
	token := mock.createTestJWT(map[string]any{"sub": "svc"}, time.Now().Add(time.Hour))
	if _, err := p.Verifier.Verify(ctx, token); err != nil {
		t.Fatalf("Verifier.Verify with default algs (RS256 token): %v", err)
	}
}

// TestOIDCModule_Init_JWKSUri verifies that parseProviderConfig + module Init
// correctly propagates jwksUri and signingAlgorithms from the raw config map.
func TestOIDCModule_Init_JWKSUri(t *testing.T) {
	mock := newMockOIDCServer(t, "app-b")
	defer mock.close()

	registry := NewProviderRegistry()
	mod := newOIDCModule("verifier", map[string]any{
		"providers": []any{
			map[string]any{
				"name":              "app-a",
				"type":              "generic",
				"issuer":            mock.issuer,
				"jwksUri":           mock.issuer + "/keys",
				"clientId":          "app-b",
				"signingAlgorithms": []any{"RS256"},
			},
		},
	}, registry)

	if err := mod.Init(); err != nil {
		t.Fatalf("module Init with jwksUri config: %v", err)
	}

	p, ok := registry.Get("app-a")
	if !ok {
		t.Fatal("expected provider 'app-a' registered after Init")
	}
	if p.Verifier == nil {
		t.Fatal("provider verifier is nil after jwksUri init")
	}

	// Verify a token through the registered provider to confirm end-to-end.
	token := mock.createTestJWT(map[string]any{"sub": "svc"}, time.Now().Add(time.Hour))
	ctx := context.Background()
	if _, err := p.Verifier.Verify(ctx, token); err != nil {
		t.Fatalf("module-registered provider Verify: %v", err)
	}
}

// --- helper: sign a JWT with an arbitrary key (for aud/iss-mismatch tests) ---

func signTestJWT(t *testing.T, key *rsa.PrivateKey, header map[string]string, claims map[string]any) string {
	t.Helper()
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("signTestJWT: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Suppress unused-import lint for math/big (used indirectly via mockOIDCServer
// which is in oidc_test.go in the same package).
var _ = big.NewInt
