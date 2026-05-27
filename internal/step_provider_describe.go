package internal

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type authProviderDescribeStep struct {
	name     string
	config   map[string]any
	registry *ProviderRegistry
}

func newAuthProviderDescribeStep(name string, config map[string]any, registry *ProviderRegistry) sdk.StepInstance {
	return &authProviderDescribeStep{name: name, config: config, registry: registry}
}

func (s *authProviderDescribeStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	configs := providerConfigsFromMaps(s.config, current)
	if len(configs) == 0 && s.registry != nil {
		configs = providerConfigsFromRegistry(s.registry)
	}
	providers := make([]map[string]any, 0, len(configs))
	for _, cfg := range configs {
		providers = append(providers, ssoAuthProviderDescriptor(cfg))
	}
	sort.Slice(providers, func(i, j int) bool {
		return fmt.Sprint(providers[i]["id"]) < fmt.Sprint(providers[j]["id"])
	})
	return &sdk.StepResult{Output: map[string]any{"providers": providers}}, nil
}

func providerConfigsFromMaps(sources ...map[string]any) []ProviderConfig {
	var configs []ProviderConfig
	for _, source := range sources {
		if source == nil {
			continue
		}
		for _, raw := range []any{source["providers"], source["providerConfigs"]} {
			configs = append(configs, providerConfigsFromValue(raw)...)
		}
	}
	return configs
}

func providerConfigsFromValue(raw any) []ProviderConfig {
	switch typed := raw.(type) {
	case []any:
		configs := make([]ProviderConfig, 0, len(typed))
		for _, item := range typed {
			if itemMap, ok := item.(map[string]any); ok {
				configs = append(configs, normalizeProviderConfig(parseProviderConfig(itemMap)))
			}
		}
		return configs
	case []map[string]any:
		configs := make([]ProviderConfig, 0, len(typed))
		for _, item := range typed {
			configs = append(configs, normalizeProviderConfig(parseProviderConfig(item)))
		}
		return configs
	default:
		return nil
	}
}

func providerConfigsFromRegistry(registry *ProviderRegistry) []ProviderConfig {
	registered := registry.All()
	configs := make([]ProviderConfig, 0, len(registered))
	for _, provider := range registered {
		if provider == nil {
			continue
		}
		configs = append(configs, ProviderConfig{
			Name:        provider.ProviderName,
			Type:        "generic",
			Issuer:      provider.Issuer,
			ClientID:    provider.OAuthCfg.ClientID,
			RedirectURL: provider.OAuthCfg.RedirectURL,
			Scopes:      provider.OAuthCfg.Scopes,
		})
	}
	return configs
}

func normalizeProviderConfig(cfg ProviderConfig) ProviderConfig {
	cfg.Type = strings.ToLower(strings.TrimSpace(cfg.Type))
	switch cfg.Type {
	case "auth0":
		cfg.Issuer = Auth0Issuer(cfg.Domain)
		if cfg.ClaimMapping.Email == "" {
			cfg.ClaimMapping = Auth0DefaultClaimMapping()
		}
	case "entra":
		cfg.Issuer = EntraIssuer(cfg.TenantID)
		if cfg.ClaimMapping.Email == "" {
			cfg.ClaimMapping = EntraDefaultClaimMapping()
		}
	case "okta":
		cfg.Issuer = OktaIssuer(cfg.Domain, cfg.AuthServerID)
		if cfg.ClaimMapping.Email == "" {
			cfg.ClaimMapping = OktaDefaultClaimMapping()
		}
	case "", "generic":
		cfg.Type = "generic"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	return cfg
}

func ssoAuthProviderDescriptor(cfg ProviderConfig) map[string]any {
	id := providerDescriptorID(cfg)
	label := providerDescriptorLabel(cfg)
	prefix := providerConfigPrefix(id)
	disabledReason := providerDisabledReason(cfg)
	supported := disabledReason == ""
	return map[string]any{
		"id":              id,
		"label":           label,
		"description":     label + " OpenID Connect login and token validation.",
		"categories":      []string{"oauth2_oidc"},
		"implementation":  "workflow-plugin-sso",
		"version":         Version,
		"docs_url":        "https://github.com/GoCodeAlone/workflow-plugin-sso",
		"support_level":   "runtime",
		"disabled_reason": disabledReason,
		"capabilities": []map[string]any{
			{
				"key":                id + "_oidc_login",
				"label":              label + " OIDC login",
				"category":           "oauth2_oidc",
				"description":        "Authorize users through " + label + " using authorization code and PKCE.",
				"supported":          supported,
				"disabled_reason":    disabledReason,
				"app_scopes":         append([]string(nil), cfg.Scopes...),
				"admin_read_scopes":  []string{"admin.auth.providers.read"},
				"admin_write_scopes": []string{"admin.auth.providers.write"},
				"config_fields":      oidcProviderConfigFields(prefix, cfg, label),
			},
		},
	}
}

func oidcProviderConfigFields(prefix string, cfg ProviderConfig, label string) []map[string]any {
	return []map[string]any{
		authProviderConfigFieldMap(prefix+"_oauth_issuer", label+" issuer", "select", "OIDC issuer URL discovered by the SSO provider.", "Choose the issuer that matches the provider application.", false, true, []map[string]any{{"value": cfg.Issuer, "label": cfg.Issuer}}),
		authProviderConfigFieldMap(prefix+"_oauth_client_id", label+" client ID", "text", "OIDC client identifier.", "Use the client ID from the provider application.", false, true, nil),
		authProviderConfigFieldMap(prefix+"_oauth_client_secret", label+" client secret", "secret", "OIDC client secret.", "Write-only. Leave blank to keep an existing configured value.", true, true, nil),
		authProviderConfigFieldMap(prefix+"_oauth_redirect_url", label+" redirect URL", "url", "Callback URL registered with the provider.", "Must match the provider application redirect URI.", false, true, nil),
	}
}

func authProviderConfigFieldMap(key, label, inputType, description, helpText string, secret, required bool, options []map[string]any) map[string]any {
	return map[string]any{
		"key":         key,
		"label":       label,
		"input_type":  inputType,
		"description": description,
		"help_text":   helpText,
		"secret":      secret,
		"required":    required,
		"options":     options,
	}
}

func providerDescriptorID(cfg ProviderConfig) string {
	name := strings.TrimSpace(cfg.Name)
	if name != "" {
		return strings.ToLower(name)
	}
	if cfg.Type != "" {
		return cfg.Type
	}
	return "generic"
}

func providerConfigPrefix(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	id = nonConfigKeyChar.ReplaceAllString(id, "_")
	id = strings.Trim(id, "_")
	if id == "" {
		return "oidc"
	}
	return id
}

var nonConfigKeyChar = regexp.MustCompile(`[^a-z0-9]+`)

func providerDescriptorLabel(cfg ProviderConfig) string {
	if cfg.Name != "" {
		return cfg.Name
	}
	switch cfg.Type {
	case "auth0":
		return "Auth0"
	case "entra":
		return "Microsoft Entra ID"
	case "okta":
		return "Okta"
	default:
		return "Generic OIDC"
	}
}

func providerDisabledReason(cfg ProviderConfig) string {
	if cfg.Issuer == "" {
		return "issuer is required"
	}
	return ""
}

type authProviderDescriptor struct {
	ID             string
	Label          string
	Categories     []string
	DisabledReason string
	Capabilities   []authProviderCapability
}

type authProviderCapability struct {
	Key          string
	Supported    bool
	AppScopes    []string
	ConfigFields []authProviderConfigField
}

type authProviderConfigField struct {
	Key     string
	Options []authProviderConfigOption
}

type authProviderConfigOption struct {
	Value string
}

func parseAuthProviderDescriptor(values map[string]any) authProviderDescriptor {
	provider := authProviderDescriptor{
		ID:             stringValue(values["id"]),
		Label:          stringValue(values["label"]),
		Categories:     stringSliceValue(values["categories"]),
		DisabledReason: stringValue(values["disabled_reason"]),
	}
	for _, item := range mapSliceValue(values["capabilities"]) {
		capability := authProviderCapability{
			Key:       stringValue(item["key"]),
			Supported: boolValue(item["supported"]),
			AppScopes: stringSliceValue(item["app_scopes"]),
		}
		for _, fieldMap := range mapSliceValue(item["config_fields"]) {
			field := authProviderConfigField{Key: stringValue(fieldMap["key"])}
			for _, optionMap := range mapSliceValue(fieldMap["options"]) {
				field.Options = append(field.Options, authProviderConfigOption{Value: stringValue(optionMap["value"])})
			}
			capability.ConfigFields = append(capability.ConfigFields, field)
		}
		provider.Capabilities = append(provider.Capabilities, capability)
	}
	return provider
}

func mapSliceValue(value any) []map[string]any {
	switch typed := value.(type) {
	case []map[string]any:
		return typed
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if itemMap, ok := item.(map[string]any); ok {
				out = append(out, itemMap)
			}
		}
		return out
	default:
		return nil
	}
}
