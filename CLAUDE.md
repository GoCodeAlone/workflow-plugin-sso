# CLAUDE.md — workflow-plugin-sso

Enterprise SSO via OpenID Connect. Supports Entra ID, Okta, and generic OIDC providers.

## Build & Test

```sh
go build ./...
go test ./... -v -race -count=1
```

## Structure

- `cmd/workflow-plugin-sso/main.go` — Entry point (`sdk.Serve`)
- `internal/plugin.go` — PluginProvider + ModuleProvider + StepProvider
- `internal/oidc.go` — OIDC provider registry and claim mapping
- `internal/module_oidc.go` — `sso.oidc` module (OIDC discovery + JWKS)
- `internal/entra_provider.go` — Entra ID (Azure AD) helpers
- `internal/okta_provider.go` — Okta issuer helpers
- `internal/generic_provider.go` — Generic OIDC provider helpers
- `internal/step_registry.go` — Step type dispatch
- `internal/step_validate_token.go` — `step.sso_validate_token`
- `internal/step_userinfo.go` — `step.sso_userinfo`
- `internal/step_token_exchange.go` — `step.sso_token_exchange`
- `internal/step_refresh_token.go` — `step.sso_refresh_token`

## Releasing

```sh
git tag v0.1.0
git push origin v0.1.0
```
