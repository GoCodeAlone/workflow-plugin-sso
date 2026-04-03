package internal

import (
	"context"
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"golang.org/x/oauth2"
)

type userInfoStep struct {
	name     string
	config   map[string]any
	registry *ProviderRegistry
}

func newUserInfoStep(name string, config map[string]any, registry *ProviderRegistry) sdk.StepInstance {
	return &userInfoStep{name: name, config: config, registry: registry}
}

func (s *userInfoStep) Execute(ctx context.Context, triggerData map[string]any, stepOutputs map[string]map[string]any, current map[string]any, metadata map[string]any, config map[string]any) (*sdk.StepResult, error) {
	providerName := resolveStringConfigFirst(current, config, "provider")
	accessToken := resolveString(current, config, "accessToken")

	if providerName == "" {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   "step.sso_userinfo: 'provider' is required",
		}}, nil
	}
	if accessToken == "" {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   "step.sso_userinfo: 'accessToken' is required",
		}}, nil
	}

	provider, ok := s.registry.Get(providerName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   fmt.Sprintf("step.sso_userinfo: provider %q not found", providerName),
		}}, nil
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	})

	userInfo, err := provider.Provider.UserInfo(ctx, tokenSource)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   fmt.Sprintf("step.sso_userinfo: UserInfo call failed: %v", err),
		}}, nil
	}

	var allClaims map[string]any
	if err := userInfo.Claims(&allClaims); err != nil {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   fmt.Sprintf("step.sso_userinfo: failed to extract claims: %v", err),
		}}, nil
	}

	return &sdk.StepResult{Output: map[string]any{
		"success": true,
		"sub":     userInfo.Subject,
		"email":   userInfo.Email,
		"profile": userInfo.Profile,
		"claims":  allClaims,
	}}, nil
}
