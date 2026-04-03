package internal

import (
	"context"
	"fmt"
	"time"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"golang.org/x/oauth2"
)

type refreshTokenStep struct {
	name     string
	config   map[string]any
	registry *ProviderRegistry
}

func newRefreshTokenStep(name string, config map[string]any, registry *ProviderRegistry) sdk.StepInstance {
	return &refreshTokenStep{name: name, config: config, registry: registry}
}

func (s *refreshTokenStep) Execute(ctx context.Context, triggerData map[string]any, stepOutputs map[string]map[string]any, current map[string]any, metadata map[string]any, config map[string]any) (*sdk.StepResult, error) {
	providerName := resolveString(current, config, "provider")
	refreshToken := resolveString(current, config, "refreshToken")

	if providerName == "" {
		return nil, fmt.Errorf("step.sso_refresh_token: 'provider' is required")
	}
	if refreshToken == "" {
		return nil, fmt.Errorf("step.sso_refresh_token: 'refreshToken' is required")
	}

	provider, ok := s.registry.Get(providerName)
	if !ok {
		return nil, fmt.Errorf("step.sso_refresh_token: provider %q not found", providerName)
	}

	oldToken := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	tokenSource := provider.OAuthCfg.TokenSource(ctx, oldToken)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("step.sso_refresh_token: token refresh failed: %w", err)
	}

	output := map[string]any{
		"accessToken": newToken.AccessToken,
		"expiresIn":   int(time.Until(newToken.Expiry).Seconds()),
	}

	if newToken.RefreshToken != "" {
		output["refreshToken"] = newToken.RefreshToken
	}

	return &sdk.StepResult{Output: output}, nil
}
