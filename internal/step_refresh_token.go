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
	providerName := resolveStringConfigFirst(current, config, "provider")
	refreshToken := resolveString(current, config, "refreshToken")

	if providerName == "" {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   "step.sso_refresh_token: 'provider' is required",
		}}, nil
	}
	if refreshToken == "" {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   "step.sso_refresh_token: 'refreshToken' is required",
		}}, nil
	}

	provider, ok := s.registry.Get(providerName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   fmt.Sprintf("step.sso_refresh_token: provider %q not found", providerName),
		}}, nil
	}

	oldToken := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	tokenSource := provider.OAuthCfg.TokenSource(ctx, oldToken)
	newToken, err := tokenSource.Token()
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   fmt.Sprintf("step.sso_refresh_token: token refresh failed: %v", err),
		}}, nil
	}

	output := map[string]any{
		"success":     true,
		"accessToken": newToken.AccessToken,
		"expiresIn":   int(time.Until(newToken.Expiry).Seconds()),
	}

	if newToken.RefreshToken != "" {
		output["refreshToken"] = newToken.RefreshToken
	}

	return &sdk.StepResult{Output: output}, nil
}
