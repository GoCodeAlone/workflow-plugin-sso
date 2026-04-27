package internal_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-sso/internal"
	"github.com/GoCodeAlone/workflow-plugin-sso/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
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

func TestNewPlugin_ImplementsStrictContractProviders(t *testing.T) {
	var _ sdk.TypedModuleProvider = internal.NewPlugin()
	var _ sdk.TypedStepProvider = internal.NewPlugin()
	var _ sdk.ContractProvider = internal.NewPlugin()
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

func TestContractRegistryDeclaresStrictContracts(t *testing.T) {
	provider := internal.NewPlugin()
	registry := provider.ContractRegistry()
	if registry == nil {
		t.Fatal("expected contract registry")
	}
	files, err := protodesc.NewFiles(registry.FileDescriptorSet)
	if err != nil {
		t.Fatalf("descriptor set: %v", err)
	}
	manifestContracts := loadManifestContracts(t)
	contractsByKey := map[string]*pb.ContractDescriptor{}
	for _, contract := range registry.Contracts {
		if contract.Mode != pb.ContractMode_CONTRACT_MODE_STRICT_PROTO {
			t.Fatalf("%s mode = %s, want strict", contractKey(contract), contract.Mode)
		}
		key := contractKey(contract)
		if _, exists := contractsByKey[key]; exists {
			t.Fatalf("duplicate runtime contract %q", key)
		}
		contractsByKey[key] = contract
		for _, name := range []string{contract.ConfigMessage, contract.InputMessage, contract.OutputMessage} {
			if name == "" {
				continue
			}
			if _, err := files.FindDescriptorByName(protoreflect.FullName(name)); err != nil {
				t.Fatalf("%s references unknown descriptor %s: %v", key, name, err)
			}
		}
		want, ok := manifestContracts[key]
		if !ok {
			t.Fatalf("%s missing from plugin.contracts.json", key)
		}
		if want.ConfigMessage != contract.ConfigMessage || want.InputMessage != contract.InputMessage || want.OutputMessage != contract.OutputMessage {
			t.Fatalf("%s manifest = %#v runtime = %#v", key, want, contract)
		}
	}
	if len(contractsByKey) != len(manifestContracts) {
		t.Fatalf("runtime contract count = %d, manifest = %d", len(contractsByKey), len(manifestContracts))
	}
}

func TestTypedProvidersValidateConfigs(t *testing.T) {
	provider := internal.NewPlugin()
	moduleConfig, err := anypb.New(&contracts.OIDCModuleConfig{Providers: []*contracts.ProviderConfig{{Name: "main", Type: "generic", Issuer: "https://issuer.example"}}})
	if err != nil {
		t.Fatalf("pack module config: %v", err)
	}
	if _, err := provider.CreateTypedModule("sso.oidc", "oidc", moduleConfig); err != nil {
		t.Fatalf("CreateTypedModule: %v", err)
	}
	wrongConfig, err := anypb.New(&contracts.UserInfoConfig{Provider: "main"})
	if err != nil {
		t.Fatalf("pack wrong config: %v", err)
	}
	if _, err := provider.CreateTypedModule("sso.oidc", "oidc", wrongConfig); err == nil {
		t.Fatal("CreateTypedModule accepted wrong typed config")
	}
	if _, err := provider.CreateTypedStep("step.sso_userinfo", "userinfo", wrongConfig); err != nil {
		t.Fatalf("CreateTypedStep: %v", err)
	}
	if _, err := provider.CreateTypedStep("step.sso_userinfo", "userinfo", moduleConfig); err == nil {
		t.Fatal("CreateTypedStep accepted wrong typed config")
	}
}

func TestTypedStepConfigProviderOverridesInput(t *testing.T) {
	result, err := internal.TypedUserInfoForTest(internal.NewProviderRegistry())(context.Background(), sdk.TypedStepRequest[*contracts.UserInfoConfig, *contracts.UserInfoInput]{
		Config: &contracts.UserInfoConfig{Provider: "admin-provider"},
		Input:  &contracts.UserInfoInput{Provider: "request-provider", AccessToken: "token"},
	})
	if err != nil {
		t.Fatalf("typed userinfo: %v", err)
	}
	if result.Output.GetSuccess() {
		t.Fatal("expected userinfo to fail without a registered provider")
	}
	if got := result.Output.GetError(); got != `step.sso_userinfo: provider "admin-provider" not found` {
		t.Fatalf("error = %q, want admin-provider lookup", got)
	}
}

type manifestContract struct {
	Mode          string `json:"mode"`
	ConfigMessage string `json:"config"`
	InputMessage  string `json:"input"`
	OutputMessage string `json:"output"`
}

func loadManifestContracts(t *testing.T) map[string]manifestContract {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "plugin.contracts.json"))
	if err != nil {
		t.Fatalf("read plugin.contracts.json: %v", err)
	}
	var manifest struct {
		Version   string `json:"version"`
		Contracts []struct {
			Kind string `json:"kind"`
			Type string `json:"type"`
			manifestContract
		} `json:"contracts"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse plugin.contracts.json: %v", err)
	}
	if manifest.Version != "v1" {
		t.Fatalf("plugin.contracts.json version = %q, want v1", manifest.Version)
	}
	out := make(map[string]manifestContract, len(manifest.Contracts))
	for _, contract := range manifest.Contracts {
		if contract.Mode != "strict" {
			t.Fatalf("%s mode = %q, want strict", contract.Type, contract.Mode)
		}
		key := contract.Kind + ":" + contract.Type
		if _, exists := out[key]; exists {
			t.Fatalf("duplicate manifest contract %q", key)
		}
		out[key] = contract.manifestContract
	}
	return out
}

func contractKey(contract *pb.ContractDescriptor) string {
	switch contract.Kind {
	case pb.ContractKind_CONTRACT_KIND_MODULE:
		return "module:" + contract.ModuleType
	case pb.ContractKind_CONTRACT_KIND_STEP:
		return "step:" + contract.StepType
	default:
		return contract.Kind.String()
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
		"step.sso_userinfo":       true,
		"step.sso_token_exchange": true,
		"step.sso_refresh_token":  true,
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
