package main

import (
	"github.com/GoCodeAlone/workflow-plugin-sso/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewPlugin())
}
