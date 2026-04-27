package internal

import (
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-sso/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// Version is set at build time via -ldflags
// "-X github.com/GoCodeAlone/workflow-plugin-sso/internal.Version=X.Y.Z"
var Version = "dev"

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
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "Enterprise SSO via OpenID Connect (Entra ID, Okta, generic OIDC)",
	}
}

func (p *ssoPlugin) ModuleTypes() []string {
	return []string{"sso.oidc"}
}

func (p *ssoPlugin) TypedModuleTypes() []string {
	return p.ModuleTypes()
}

func (p *ssoPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	if typeName != "sso.oidc" {
		return nil, fmt.Errorf("unknown module type: %s", typeName)
	}
	return newOIDCModule(name, config, p.registry), nil
}

func (p *ssoPlugin) CreateTypedModule(typeName, name string, config *anypb.Any) (sdk.ModuleInstance, error) {
	if typeName != "sso.oidc" {
		return nil, fmt.Errorf("unknown typed module type: %s", typeName)
	}
	factory := sdk.NewTypedModuleFactory(typeName, &contracts.OIDCModuleConfig{}, func(name string, cfg *contracts.OIDCModuleConfig) (sdk.ModuleInstance, error) {
		return newOIDCModule(name, oidcModuleConfigToMap(cfg), p.registry), nil
	})
	return factory.CreateTypedModule(typeName, name, config)
}

func (p *ssoPlugin) StepTypes() []string {
	return allStepTypes()
}

func (p *ssoPlugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	return createStep(typeName, name, config, p.registry)
}

func (p *ssoPlugin) TypedStepTypes() []string {
	return p.StepTypes()
}

func (p *ssoPlugin) CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.sso_validate_token":
		factory := sdk.NewTypedStepFactory(typeName, &contracts.ValidateTokenConfig{}, &contracts.ValidateTokenInput{}, typedValidateToken(p.registry))
		return factory.CreateTypedStep(typeName, name, config)
	case "step.sso_userinfo":
		factory := sdk.NewTypedStepFactory(typeName, &contracts.UserInfoConfig{}, &contracts.UserInfoInput{}, typedUserInfo(p.registry))
		return factory.CreateTypedStep(typeName, name, config)
	case "step.sso_token_exchange":
		factory := sdk.NewTypedStepFactory(typeName, &contracts.TokenExchangeConfig{}, &contracts.TokenExchangeInput{}, typedTokenExchange(p.registry))
		return factory.CreateTypedStep(typeName, name, config)
	case "step.sso_refresh_token":
		factory := sdk.NewTypedStepFactory(typeName, &contracts.RefreshTokenConfig{}, &contracts.RefreshTokenInput{}, typedRefreshToken(p.registry))
		return factory.CreateTypedStep(typeName, name, config)
	default:
		return nil, fmt.Errorf("unknown typed step type: %s", typeName)
	}
}

func (p *ssoPlugin) ContractRegistry() *pb.ContractRegistry {
	return ssoContractRegistry
}

var ssoContractRegistry = &pb.ContractRegistry{
	FileDescriptorSet: &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			protodesc.ToFileDescriptorProto(structpb.File_google_protobuf_struct_proto),
			protodesc.ToFileDescriptorProto(contracts.File_internal_contracts_sso_proto),
		},
	},
	Contracts: []*pb.ContractDescriptor{
		moduleContract("sso.oidc", "OIDCModuleConfig"),
		stepContract("step.sso_validate_token", "ValidateTokenConfig", "ValidateTokenInput", "ValidateTokenOutput"),
		stepContract("step.sso_userinfo", "UserInfoConfig", "UserInfoInput", "UserInfoOutput"),
		stepContract("step.sso_token_exchange", "TokenExchangeConfig", "TokenExchangeInput", "TokenExchangeOutput"),
		stepContract("step.sso_refresh_token", "RefreshTokenConfig", "RefreshTokenInput", "RefreshTokenOutput"),
	},
}

func moduleContract(moduleType, configMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.sso.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_MODULE,
		ModuleType:    moduleType,
		ConfigMessage: pkg + configMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

func stepContract(stepType, configMessage, inputMessage, outputMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.sso.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_STEP,
		StepType:      stepType,
		ConfigMessage: pkg + configMessage,
		InputMessage:  pkg + inputMessage,
		OutputMessage: pkg + outputMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}
