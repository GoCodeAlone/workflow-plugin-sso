package internal

import (
	"context"
	"fmt"
	"strings"
	"time"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type validateTokenStep struct {
	name     string
	config   map[string]any
	registry *ProviderRegistry
}

func newValidateTokenStep(name string, config map[string]any, registry *ProviderRegistry) sdk.StepInstance {
	return &validateTokenStep{name: name, config: config, registry: registry}
}

func (s *validateTokenStep) Execute(ctx context.Context, triggerData map[string]any, stepOutputs map[string]map[string]any, current map[string]any, metadata map[string]any, config map[string]any) (*sdk.StepResult, error) {
	rawToken := resolveString(current, config, "token")

	// Fall back to Authorization header
	if rawToken == "" {
		if auth := resolveString(current, config, "authorization"); auth != "" {
			rawToken = strings.TrimPrefix(auth, "Bearer ")
		}
	}

	if rawToken == "" {
		return &sdk.StepResult{Output: map[string]any{
			"valid": false,
			"error": "no token provided",
		}}, nil
	}

	// Determine provider
	providerName := resolveString(current, config, "provider")
	var provider *OIDCProvider

	if providerName != "" {
		p, ok := s.registry.Get(providerName)
		if !ok {
			return &sdk.StepResult{Output: map[string]any{
				"valid": false,
				"error": fmt.Sprintf("provider %q not found", providerName),
			}}, nil
		}
		provider = p
	} else {
		// Auto-detect from iss claim
		iss, err := DecodeUnverifiedIssuer(rawToken)
		if err != nil {
			return &sdk.StepResult{Output: map[string]any{
				"valid": false,
				"error": fmt.Sprintf("cannot determine provider: %v", err),
			}}, nil
		}
		p, ok := s.registry.FindByIssuer(iss)
		if !ok {
			return &sdk.StepResult{Output: map[string]any{
				"valid": false,
				"error": fmt.Sprintf("no registered provider for issuer %q", iss),
			}}, nil
		}
		provider = p
	}

	// Verify the token
	idToken, err := provider.Verifier.Verify(ctx, rawToken)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{
			"valid": false,
			"error": fmt.Sprintf("token verification failed: %v", err),
		}}, nil
	}

	// Extract all claims
	var allClaims map[string]any
	if err := idToken.Claims(&allClaims); err != nil {
		return &sdk.StepResult{Output: map[string]any{
			"valid": false,
			"error": fmt.Sprintf("failed to extract claims: %v", err),
		}}, nil
	}

	email, name, roles, groups := ExtractClaims(allClaims, provider.ClaimPaths)

	return &sdk.StepResult{Output: map[string]any{
		"valid":     true,
		"userId":    idToken.Subject,
		"email":     email,
		"name":      name,
		"roles":     roles,
		"groups":    groups,
		"provider":  provider.ProviderName,
		"claims":    allClaims,
		"expiresAt": idToken.Expiry.Format(time.RFC3339),
	}}, nil
}

func resolveString(current, config map[string]any, key string) string {
	if v, ok := current[key].(string); ok && v != "" {
		return v
	}
	if v, ok := config[key].(string); ok && v != "" {
		return v
	}
	return ""
}
