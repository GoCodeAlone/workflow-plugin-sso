package internal

import (
	"context"
	"fmt"
	"time"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type tokenExchangeStep struct {
	name     string
	config   map[string]any
	registry *ProviderRegistry
}

func newTokenExchangeStep(name string, config map[string]any, registry *ProviderRegistry) sdk.StepInstance {
	return &tokenExchangeStep{name: name, config: config, registry: registry}
}

func (s *tokenExchangeStep) Execute(ctx context.Context, triggerData map[string]any, stepOutputs map[string]map[string]any, current map[string]any, metadata map[string]any, config map[string]any) (*sdk.StepResult, error) {
	providerName := resolveStringConfigFirst(current, config, "provider")
	code := resolveString(current, config, "code")

	if providerName == "" {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   "step.sso_token_exchange: 'provider' is required",
		}}, nil
	}
	if code == "" {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   "step.sso_token_exchange: 'code' is required",
		}}, nil
	}

	provider, ok := s.registry.Get(providerName)
	if !ok {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   fmt.Sprintf("step.sso_token_exchange: provider %q not found", providerName),
		}}, nil
	}

	token, err := provider.OAuthCfg.Exchange(ctx, code)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   fmt.Sprintf("step.sso_token_exchange: code exchange failed: %v", err),
		}}, nil
	}

	output := map[string]any{
		"success":     true,
		"accessToken": token.AccessToken,
		"tokenType":   token.TokenType,
		"expiresIn":   int(time.Until(token.Expiry).Seconds()),
	}

	if token.RefreshToken != "" {
		output["refreshToken"] = token.RefreshToken
	}

	// Extract id_token from extras
	if rawIDToken, ok := token.Extra("id_token").(string); ok {
		output["idToken"] = rawIDToken
	}

	return &sdk.StepResult{Output: output}, nil
}
