package internal

import (
	"context"
	"fmt"
	"log"
)

// oidcModule implements sdk.ModuleInstance for the "sso.oidc" module type.
type oidcModule struct {
	name                string
	config              map[string]any
	registry            *ProviderRegistry
	registeredProviders []string
}

func newOIDCModule(name string, config map[string]any, registry *ProviderRegistry) *oidcModule {
	return &oidcModule{
		name:     name,
		config:   config,
		registry: registry,
	}
}

func (m *oidcModule) Init() error {
	providers, ok := m.config["providers"]
	if !ok {
		return fmt.Errorf("sso.oidc module %q: 'providers' config is required", m.name)
	}

	providerList, ok := providers.([]any)
	if !ok {
		return fmt.Errorf("sso.oidc module %q: 'providers' must be a list", m.name)
	}

	ctx := context.Background()
	for i, raw := range providerList {
		pCfg, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("sso.oidc module %q: provider[%d] must be a map", m.name, i)
		}

		cfg := parseProviderConfig(pCfg)
		if cfg.Name == "" {
			cfg.Name = fmt.Sprintf("%s-provider-%d", m.name, i)
		}

		// Resolve issuer from provider type helpers
		switch cfg.Type {
		case "entra":
			cfg.Issuer = EntraIssuer(cfg.TenantID)
			if cfg.ClaimMapping.Groups == "" {
				cfg.ClaimMapping.Groups = "groups"
			}
			if cfg.ClaimMapping.Roles == "" {
				cfg.ClaimMapping.Roles = "roles"
			}
		case "okta":
			cfg.Issuer = OktaIssuer(cfg.Domain, cfg.AuthServerID)
			if cfg.ClaimMapping.Groups == "" {
				cfg.ClaimMapping.Groups = "groups"
			}
		case "generic", "":
			// issuer must be set directly
		default:
			log.Printf("sso.oidc: unknown provider type %q, treating as generic", cfg.Type)
		}

		p, err := InitProvider(ctx, cfg)
		if err != nil {
			return fmt.Errorf("sso.oidc module %q: %w", m.name, err)
		}
		m.registry.Register(p)
		m.registeredProviders = append(m.registeredProviders, p.ProviderName)
		log.Printf("sso.oidc: registered provider %q (issuer: %s)", p.ProviderName, p.Issuer)
	}

	return nil
}

func (m *oidcModule) Start(_ context.Context) error {
	return nil
}

func (m *oidcModule) Stop(_ context.Context) error {
	for _, name := range m.registeredProviders {
		m.registry.Remove(name)
	}
	return nil
}

func parseProviderConfig(raw map[string]any) ProviderConfig {
	cfg := ProviderConfig{
		Name:         getString(raw, "name"),
		Type:         getString(raw, "type"),
		Issuer:       getString(raw, "issuer"),
		ClientID:     getString(raw, "clientId"),
		ClientSecret: getString(raw, "clientSecret"),
		RedirectURL:  getString(raw, "redirectUrl"),
		TenantID:     getString(raw, "tenantId"),
		Domain:       getString(raw, "domain"),
		AuthServerID: getString(raw, "authServerId"),
	}

	if scopes, ok := raw["scopes"].([]any); ok {
		for _, s := range scopes {
			if str, ok := s.(string); ok {
				cfg.Scopes = append(cfg.Scopes, str)
			}
		}
	}

	if cm, ok := raw["claimMapping"].(map[string]any); ok {
		cfg.ClaimMapping = ClaimMapping{
			Roles:  getString(cm, "roles"),
			Groups: getString(cm, "groups"),
			Email:  getString(cm, "email"),
			Name:   getString(cm, "name"),
		}
	}

	return cfg
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
