package internal

import (
	"github.com/GoCodeAlone/workflow-plugin-sso/internal/contracts"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func TypedUserInfoForTest(registry *ProviderRegistry) sdk.TypedStepHandler[*contracts.UserInfoConfig, *contracts.UserInfoInput, *contracts.UserInfoOutput] {
	return typedUserInfo(registry)
}
