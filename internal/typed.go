package internal

import (
	"context"

	"github.com/GoCodeAlone/workflow-plugin-sso/internal/contracts"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/structpb"
)

func typedValidateToken(registry *ProviderRegistry) sdk.TypedStepHandler[*contracts.ValidateTokenConfig, *contracts.ValidateTokenInput, *contracts.ValidateTokenOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.ValidateTokenConfig, *contracts.ValidateTokenInput]) (*sdk.TypedStepResult[*contracts.ValidateTokenOutput], error) {
		config := validateTokenConfigToMap(req.Config)
		current := mergeMaps(req.Current, validateTokenInputToMap(req.Input))
		step := newValidateTokenStep("", nil, registry)
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, current, req.Metadata, config)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.ValidateTokenOutput]{Output: validateTokenOutputFromMap(result.Output), StopPipeline: result.StopPipeline}, nil
	}
}

func typedUserInfo(registry *ProviderRegistry) sdk.TypedStepHandler[*contracts.UserInfoConfig, *contracts.UserInfoInput, *contracts.UserInfoOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.UserInfoConfig, *contracts.UserInfoInput]) (*sdk.TypedStepResult[*contracts.UserInfoOutput], error) {
		config := userInfoConfigToMap(req.Config)
		current := mergeMaps(req.Current, userInfoInputToMap(req.Input))
		step := newUserInfoStep("", nil, registry)
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, current, req.Metadata, config)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.UserInfoOutput]{Output: userInfoOutputFromMap(result.Output), StopPipeline: result.StopPipeline}, nil
	}
}

func typedTokenExchange(registry *ProviderRegistry) sdk.TypedStepHandler[*contracts.TokenExchangeConfig, *contracts.TokenExchangeInput, *contracts.TokenExchangeOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.TokenExchangeConfig, *contracts.TokenExchangeInput]) (*sdk.TypedStepResult[*contracts.TokenExchangeOutput], error) {
		config := tokenExchangeConfigToMap(req.Config)
		current := mergeMaps(req.Current, tokenExchangeInputToMap(req.Input))
		step := newTokenExchangeStep("", nil, registry)
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, current, req.Metadata, config)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.TokenExchangeOutput]{Output: tokenOutputFromMap(result.Output), StopPipeline: result.StopPipeline}, nil
	}
}

func typedRefreshToken(registry *ProviderRegistry) sdk.TypedStepHandler[*contracts.RefreshTokenConfig, *contracts.RefreshTokenInput, *contracts.RefreshTokenOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.RefreshTokenConfig, *contracts.RefreshTokenInput]) (*sdk.TypedStepResult[*contracts.RefreshTokenOutput], error) {
		config := refreshTokenConfigToMap(req.Config)
		current := mergeMaps(req.Current, refreshTokenInputToMap(req.Input))
		step := newRefreshTokenStep("", nil, registry)
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, current, req.Metadata, config)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.RefreshTokenOutput]{Output: refreshTokenOutputFromMap(result.Output), StopPipeline: result.StopPipeline}, nil
	}
}

func mergeMaps(maps ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, values := range maps {
		for key, value := range values {
			out[key] = value
		}
	}
	return out
}

func oidcModuleConfigToMap(cfg *contracts.OIDCModuleConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	providers := make([]any, 0, len(cfg.GetProviders()))
	for _, provider := range cfg.GetProviders() {
		if provider == nil {
			continue
		}
		item := compactMap(map[string]any{
			"name":         provider.GetName(),
			"type":         provider.GetType(),
			"issuer":       provider.GetIssuer(),
			"clientId":     provider.GetClientId(),
			"clientSecret": provider.GetClientSecret(),
			"redirectUrl":  provider.GetRedirectUrl(),
			"tenantId":     provider.GetTenantId(),
			"domain":       provider.GetDomain(),
			"authServerId": provider.GetAuthServerId(),
			"scopes":       stringsToAny(provider.GetScopes()),
		})
		if provider.GetClaimMapping() != nil {
			item["claimMapping"] = compactMap(map[string]any{
				"roles":  provider.GetClaimMapping().GetRoles(),
				"groups": provider.GetClaimMapping().GetGroups(),
				"email":  provider.GetClaimMapping().GetEmail(),
				"name":   provider.GetClaimMapping().GetName(),
			})
		}
		providers = append(providers, item)
	}
	return map[string]any{"providers": providers}
}

func validateTokenConfigToMap(cfg *contracts.ValidateTokenConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{"provider": cfg.GetProvider()})
}

func validateTokenInputToMap(input *contracts.ValidateTokenInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{"token": input.GetToken(), "authorization": input.GetAuthorization(), "provider": input.GetProvider()})
}

func userInfoConfigToMap(cfg *contracts.UserInfoConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{"provider": cfg.GetProvider()})
}

func userInfoInputToMap(input *contracts.UserInfoInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{"accessToken": input.GetAccessToken(), "provider": input.GetProvider()})
}

func tokenExchangeConfigToMap(cfg *contracts.TokenExchangeConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{"provider": cfg.GetProvider()})
}

func tokenExchangeInputToMap(input *contracts.TokenExchangeInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{"code": input.GetCode(), "provider": input.GetProvider()})
}

func refreshTokenConfigToMap(cfg *contracts.RefreshTokenConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{"provider": cfg.GetProvider()})
}

func refreshTokenInputToMap(input *contracts.RefreshTokenInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{"refreshToken": input.GetRefreshToken(), "provider": input.GetProvider()})
}

func validateTokenOutputFromMap(values map[string]any) *contracts.ValidateTokenOutput {
	return &contracts.ValidateTokenOutput{
		Valid:     boolValue(values["valid"]),
		UserId:    stringValue(values["userId"]),
		Email:     stringValue(values["email"]),
		Name:      stringValue(values["name"]),
		Roles:     stringSliceValue(values["roles"]),
		Groups:    stringSliceValue(values["groups"]),
		Provider:  stringValue(values["provider"]),
		Claims:    structFromMap(mapValue(values["claims"])),
		ExpiresAt: stringValue(values["expiresAt"]),
		Error:     stringValue(values["error"]),
	}
}

func userInfoOutputFromMap(values map[string]any) *contracts.UserInfoOutput {
	return &contracts.UserInfoOutput{
		Success: boolValue(values["success"]),
		Sub:     stringValue(values["sub"]),
		Email:   stringValue(values["email"]),
		Profile: stringValue(values["profile"]),
		Claims:  structFromMap(mapValue(values["claims"])),
		Error:   stringValue(values["error"]),
	}
}

func tokenOutputFromMap(values map[string]any) *contracts.TokenExchangeOutput {
	return &contracts.TokenExchangeOutput{
		Success:      boolValue(values["success"]),
		AccessToken:  stringValue(values["accessToken"]),
		RefreshToken: stringValue(values["refreshToken"]),
		IdToken:      stringValue(values["idToken"]),
		TokenType:    stringValue(values["tokenType"]),
		ExpiresIn:    int32Value(values["expiresIn"]),
		Error:        stringValue(values["error"]),
	}
}

func refreshTokenOutputFromMap(values map[string]any) *contracts.RefreshTokenOutput {
	return &contracts.RefreshTokenOutput{
		Success:      boolValue(values["success"]),
		AccessToken:  stringValue(values["accessToken"]),
		RefreshToken: stringValue(values["refreshToken"]),
		ExpiresIn:    int32Value(values["expiresIn"]),
		Error:        stringValue(values["error"]),
	}
}

func compactMap(values map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range values {
		if isZeroValue(value) {
			continue
		}
		out[key] = value
	}
	return out
}

func isZeroValue(value any) bool {
	switch v := value.(type) {
	case string:
		return v == ""
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	case nil:
		return true
	default:
		return false
	}
}

func stringsToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func stringValue(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func boolValue(value any) bool {
	if b, ok := value.(bool); ok {
		return b
	}
	return false
}

func int32Value(value any) int32 {
	switch v := value.(type) {
	case int:
		return int32(v)
	case int32:
		return v
	case int64:
		return int32(v)
	case float64:
		return int32(v)
	default:
		return 0
	}
}

func stringSliceValue(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func mapValue(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return nil
}

func structFromMap(values map[string]any) *structpb.Struct {
	if len(values) == 0 {
		return nil
	}
	out, err := structpb.NewStruct(values)
	if err != nil {
		return nil
	}
	return out
}
