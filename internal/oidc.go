package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ClaimMapping defines how to extract identity fields from OIDC claims.
type ClaimMapping struct {
	Roles  string // JSON path to roles claim, e.g. "roles" or "realm_access.roles"
	Groups string // JSON path to groups claim
	Email  string // defaults to "email"
	Name   string // defaults to "name"
}

// OIDCProvider holds a configured OIDC identity provider.
type OIDCProvider struct {
	ProviderName string
	Issuer       string
	Verifier     *oidc.IDTokenVerifier
	OAuthCfg     *oauth2.Config
	Provider     *oidc.Provider
	ClaimPaths   ClaimMapping
}

// ProviderRegistry is a thread-safe map of OIDC providers keyed by name.
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]*OIDCProvider
}

// NewProviderRegistry creates an empty provider registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]*OIDCProvider),
	}
}

// Register adds a provider to the registry.
func (r *ProviderRegistry) Register(p *OIDCProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.ProviderName] = p
}

// Get retrieves a provider by name.
func (r *ProviderRegistry) Get(name string) (*OIDCProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// Remove deletes a provider from the registry.
func (r *ProviderRegistry) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.providers, name)
}

// FindByIssuer returns the first provider matching the given issuer URL.
func (r *ProviderRegistry) FindByIssuer(issuer string) (*OIDCProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.providers {
		if p.Issuer == issuer {
			return p, true
		}
	}
	return nil, false
}

// All returns all registered providers.
func (r *ProviderRegistry) All() []*OIDCProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*OIDCProvider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p)
	}
	return out
}

// InitProvider discovers OIDC endpoints and creates a verifier for a single provider config.
func InitProvider(ctx context.Context, cfg ProviderConfig) (*OIDCProvider, error) {
	issuer := cfg.Issuer
	if issuer == "" {
		return nil, fmt.Errorf("provider %q: issuer is required", cfg.Name)
	}

	oidcProvider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("provider %q: OIDC discovery failed for %s: %w", cfg.Name, issuer, err)
	}

	verifier := oidcProvider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  cfg.RedirectURL,
	}

	claimMap := cfg.ClaimMapping
	if claimMap.Email == "" {
		claimMap.Email = "email"
	}
	if claimMap.Name == "" {
		claimMap.Name = "name"
	}

	return &OIDCProvider{
		ProviderName: cfg.Name,
		Issuer:       issuer,
		Verifier:     verifier,
		OAuthCfg:     oauthCfg,
		Provider:     oidcProvider,
		ClaimPaths:   claimMap,
	}, nil
}

// ProviderConfig is the config for a single OIDC provider.
type ProviderConfig struct {
	Name         string
	Type         string // "entra", "okta", "generic"
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURL  string
	ClaimMapping ClaimMapping

	// Entra-specific
	TenantID string
	// Okta-specific
	Domain       string
	AuthServerID string
}

// ExtractClaims extracts mapped identity fields from raw OIDC claims.
func ExtractClaims(raw map[string]any, mapping ClaimMapping) (email, name string, roles, groups []string) {
	email = getStringClaim(raw, mapping.Email)
	name = getStringClaim(raw, mapping.Name)
	roles = getStringSliceClaim(raw, mapping.Roles)
	groups = getStringSliceClaim(raw, mapping.Groups)
	return
}

func getStringClaim(claims map[string]any, path string) string {
	if path == "" {
		return ""
	}
	val := getNestedClaim(claims, path)
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}

func getStringSliceClaim(claims map[string]any, path string) []string {
	if path == "" {
		return nil
	}
	val := getNestedClaim(claims, path)
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

func getNestedClaim(claims map[string]any, path string) any {
	parts := strings.Split(path, ".")
	var current any = claims
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = m[part]
	}
	return current
}

// DecodeUnverifiedIssuer extracts the "iss" claim from a JWT without verifying.
func DecodeUnverifiedIssuer(rawToken string) (string, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}
	if claims.Iss == "" {
		return "", fmt.Errorf("JWT has no iss claim")
	}
	return claims.Iss, nil
}

