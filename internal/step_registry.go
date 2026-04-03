package internal

import (
	"fmt"
	"sort"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type stepConstructor func(name string, config map[string]any, registry *ProviderRegistry) sdk.StepInstance

var stepRegistry = map[string]stepConstructor{
	"step.sso_validate_token": newValidateTokenStep,
	"step.sso_userinfo":       newUserInfoStep,
	"step.sso_token_exchange":  newTokenExchangeStep,
	"step.sso_refresh_token":   newRefreshTokenStep,
}

func allStepTypes() []string {
	types := make([]string, 0, len(stepRegistry))
	for k := range stepRegistry {
		types = append(types, k)
	}
	sort.Strings(types)
	return types
}

func createStep(typeName, name string, config map[string]any, registry *ProviderRegistry) (sdk.StepInstance, error) {
	ctor, ok := stepRegistry[typeName]
	if !ok {
		return nil, fmt.Errorf("unknown step type: %s", typeName)
	}
	return ctor(name, config, registry), nil
}
