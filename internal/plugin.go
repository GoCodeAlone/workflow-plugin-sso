package internal

import (
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type ssoPlugin struct {
	registry *ProviderRegistry
}

func NewPlugin() *ssoPlugin {
	return &ssoPlugin{
		registry: NewProviderRegistry(),
	}
}

func (p *ssoPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-sso",
		Version:     "0.1.0",
		Author:      "GoCodeAlone",
		Description: "Enterprise SSO via OpenID Connect (Entra ID, Okta, generic OIDC)",
	}
}

func (p *ssoPlugin) ModuleTypes() []string {
	return []string{"sso.oidc"}
}

func (p *ssoPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	if typeName != "sso.oidc" {
		return nil, fmt.Errorf("unknown module type: %s", typeName)
	}
	return newOIDCModule(name, config, p.registry), nil
}

func (p *ssoPlugin) StepTypes() []string {
	return allStepTypes()
}

func (p *ssoPlugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	return createStep(typeName, name, config, p.registry)
}
