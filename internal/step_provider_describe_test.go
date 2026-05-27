package internal

import (
	"context"
	"slices"
	"testing"
)

func TestAuthProviderDescribeReturnsOIDCDescriptors(t *testing.T) {
	step := newAuthProviderDescribeStep("describe", map[string]any{
		"providers": []any{
			map[string]any{
				"name":        "auth0-main",
				"type":        "auth0",
				"domain":      "tenant.auth0.com",
				"clientId":    "auth0-client",
				"redirectUrl": "https://app.example.test/auth/auth0/callback",
			},
			map[string]any{
				"name":        "entra-main",
				"type":        "entra",
				"tenantId":    "tenant-id",
				"clientId":    "entra-client",
				"redirectUrl": "https://app.example.test/auth/entra/callback",
			},
			map[string]any{
				"name":         "okta-main",
				"type":         "okta",
				"domain":       "dev-12345.okta.com",
				"authServerId": "default",
				"clientId":     "okta-client",
				"redirectUrl":  "https://app.example.test/auth/okta/callback",
			},
			map[string]any{
				"name":        "generic-main",
				"type":        "generic",
				"issuer":      "https://issuer.example.test",
				"clientId":    "generic-client",
				"redirectUrl": "https://app.example.test/auth/generic/callback",
			},
		},
	}, nil)

	result, err := step.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("describe providers: %v", err)
	}

	providers := providerDescriptorsFromOutput(t, result.Output)
	if got := len(providers); got != 4 {
		t.Fatalf("provider count = %d, want 4", got)
	}
	ids := providerDescriptorIDs(providers)
	for _, want := range []string{"auth0-main", "entra-main", "okta-main", "generic-main"} {
		if !slices.Contains(ids, want) {
			t.Fatalf("provider ids = %v, want %s", ids, want)
		}
	}
	requireProviderDescriptor(t, providers, "auth0-main", "auth0_main", "https://tenant.auth0.com/", "auth0_main_oauth_client_secret")
	requireProviderDescriptor(t, providers, "entra-main", "entra_main", "https://login.microsoftonline.com/tenant-id/v2.0", "entra_main_oauth_client_secret")
	requireProviderDescriptor(t, providers, "okta-main", "okta_main", "https://dev-12345.okta.com/oauth2/default", "okta_main_oauth_client_secret")
	requireProviderDescriptor(t, providers, "generic-main", "generic_main", "https://issuer.example.test", "generic_main_oauth_client_secret")
}

func TestAuthProviderDescribeDefaultsUnsupportedUntilConfigured(t *testing.T) {
	step := newAuthProviderDescribeStep("describe", map[string]any{
		"providers": []any{
			map[string]any{"name": "broken", "type": "auth0"},
		},
	}, nil)

	result, err := step.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("describe providers: %v", err)
	}

	provider := requireProvider(t, providerDescriptorsFromOutput(t, result.Output), "broken")
	if provider.DisabledReason == "" {
		t.Fatal("expected disabled reason for incomplete provider")
	}
	if len(provider.Capabilities) == 0 || provider.Capabilities[0].Supported {
		t.Fatalf("incomplete provider capability should be unsupported: %#v", provider.Capabilities)
	}
}

func TestAuthProviderDescribeKeepsConfigFieldsEnabledWhenSecretsMissing(t *testing.T) {
	step := newAuthProviderDescribeStep("describe", map[string]any{
		"providers": []any{
			map[string]any{"name": "auth0-main", "type": "auth0", "domain": "tenant.auth0.com"},
		},
	}, nil)

	result, err := step.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("describe providers: %v", err)
	}

	provider := requireProvider(t, providerDescriptorsFromOutput(t, result.Output), "auth0-main")
	if provider.DisabledReason != "" {
		t.Fatalf("provider disabled_reason = %q", provider.DisabledReason)
	}
	if len(provider.Capabilities) == 0 || !provider.Capabilities[0].Supported {
		t.Fatalf("provider capability should remain supported while admin fills required fields: %#v", provider.Capabilities)
	}
}

func TestAuth0Issuer(t *testing.T) {
	if got, want := Auth0Issuer("tenant.auth0.com"), "https://tenant.auth0.com/"; got != want {
		t.Fatalf("Auth0Issuer = %q, want %q", got, want)
	}
	if got, want := Auth0Issuer("https://tenant.auth0.com"), "https://tenant.auth0.com/"; got != want {
		t.Fatalf("Auth0Issuer with scheme = %q, want %q", got, want)
	}
}

func providerDescriptorsFromOutput(t *testing.T, output map[string]any) []authProviderDescriptor {
	t.Helper()
	providers, ok := output["providers"].([]map[string]any)
	if !ok {
		t.Fatalf("providers has type %T, want []map[string]any", output["providers"])
	}
	descriptors := make([]authProviderDescriptor, 0, len(providers))
	for _, provider := range providers {
		descriptors = append(descriptors, parseAuthProviderDescriptor(provider))
	}
	return descriptors
}

func providerDescriptorIDs(providers []authProviderDescriptor) []string {
	ids := make([]string, 0, len(providers))
	for _, provider := range providers {
		ids = append(ids, provider.ID)
	}
	return ids
}

func requireProviderDescriptor(t *testing.T, providers []authProviderDescriptor, id, prefix, issuer, secretKey string) {
	t.Helper()
	provider := requireProvider(t, providers, id)
	if provider.DisabledReason != "" {
		t.Fatalf("%s disabled_reason = %q", id, provider.DisabledReason)
	}
	if !slices.Contains(provider.Categories, "oauth2_oidc") {
		t.Fatalf("%s categories = %v", id, provider.Categories)
	}
	if len(provider.Capabilities) != 1 {
		t.Fatalf("%s capabilities = %#v", id, provider.Capabilities)
	}
	capability := provider.Capabilities[0]
	if !capability.Supported {
		t.Fatalf("%s capability unsupported: %#v", id, capability)
	}
	if !slices.Contains(capability.AppScopes, "openid") {
		t.Fatalf("%s app scopes = %v", id, capability.AppScopes)
	}
	keys := make([]string, 0, len(capability.ConfigFields))
	for _, field := range capability.ConfigFields {
		keys = append(keys, field.Key)
	}
	if !slices.Contains(keys, secretKey) {
		t.Fatalf("%s config field keys = %v, want %s", id, keys, secretKey)
	}
	if !slices.Contains(keys, prefix+"_oauth_issuer") {
		t.Fatalf("%s config field keys = %v, want issuer field", id, keys)
	}
	if got := providerDescriptorIssuer(capability, prefix); got != issuer {
		t.Fatalf("%s issuer = %q, want %q", id, got, issuer)
	}
}

func requireProvider(t *testing.T, providers []authProviderDescriptor, id string) authProviderDescriptor {
	t.Helper()
	for _, provider := range providers {
		if provider.ID == id {
			return provider
		}
	}
	t.Fatalf("missing provider %s in %#v", id, providers)
	return authProviderDescriptor{}
}

func providerDescriptorIssuer(capability authProviderCapability, prefix string) string {
	for _, field := range capability.ConfigFields {
		if field.Key == prefix+"_oauth_issuer" {
			for _, option := range field.Options {
				if option.Value != "" {
					return option.Value
				}
			}
		}
	}
	return ""
}
