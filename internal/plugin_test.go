package internal_test

import (
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-sso/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func TestNewPlugin_ImplementsPluginProvider(t *testing.T) {
	var _ sdk.PluginProvider = internal.NewPlugin()
}

func TestNewPlugin_ImplementsModuleProvider(t *testing.T) {
	var _ sdk.ModuleProvider = internal.NewPlugin()
}

func TestNewPlugin_ImplementsStepProvider(t *testing.T) {
	var _ sdk.StepProvider = internal.NewPlugin()
}

func TestManifest_HasRequiredFields(t *testing.T) {
	p := internal.NewPlugin()
	m := p.Manifest()
	if m.Name == "" {
		t.Error("manifest Name is empty")
	}
	if m.Version == "" {
		t.Error("manifest Version is empty")
	}
	if m.Description == "" {
		t.Error("manifest Description is empty")
	}
}

func TestModuleTypes(t *testing.T) {
	p := internal.NewPlugin()
	types := p.ModuleTypes()
	if len(types) != 1 || types[0] != "sso.oidc" {
		t.Errorf("expected [sso.oidc], got %v", types)
	}
}

func TestStepTypes(t *testing.T) {
	p := internal.NewPlugin()
	types := p.StepTypes()
	expected := map[string]bool{
		"step.sso_validate_token": true,
		"step.sso_userinfo":      true,
		"step.sso_token_exchange": true,
		"step.sso_refresh_token": true,
	}
	if len(types) != len(expected) {
		t.Fatalf("expected %d step types, got %d: %v", len(expected), len(types), types)
	}
	for _, st := range types {
		if !expected[st] {
			t.Errorf("unexpected step type: %s", st)
		}
	}
}
