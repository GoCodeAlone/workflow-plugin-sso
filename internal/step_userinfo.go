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
	providerName := resolveString(current, config, "provider")
	accessToken := resolveString(current, config, "accessToken")

	if providerName == "" {
		return nil, fmt.Errorf("step.sso_userinfo: 'provider' is required")
	}
	if accessToken == "" {
		return nil, fmt.Errorf("step.sso_userinfo: 'accessToken' is required")
	}

	provider, ok := s.registry.Get(providerName)
	if !ok {
		return nil, fmt.Errorf("step.sso_userinfo: provider %q not found", providerName)
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	})

	userInfo, err := provider.Provider.UserInfo(ctx, tokenSource)
	if err != nil {
		return nil, fmt.Errorf("step.sso_userinfo: UserInfo call failed: %w", err)
	}

	var allClaims map[string]any
	if err := userInfo.Claims(&allClaims); err != nil {
		return nil, fmt.Errorf("step.sso_userinfo: failed to extract claims: %w", err)
	}

	return &sdk.StepResult{Output: map[string]any{
		"sub":     userInfo.Subject,
		"email":   userInfo.Email,
		"profile": userInfo.Profile,
		"claims":  allClaims,
	}}, nil
}
