# workflow-plugin-sso

> ⚠️ **Experimental** — This plugin compiles and passes its unit tests but has not been validated in any active GoCodeAlone-internal production deployment. Use with caution. Please [open an issue](https://github.com/GoCodeAlone/workflow-plugin-sso/issues/new) if you adopt it so we can promote it to **verified** status.

Generic OpenID Connect runtime for Workflow applications. The plugin registers
OIDC providers, validates ID tokens, exchanges authorization codes, fetches
userinfo, refreshes tokens, and exports auth-provider descriptors for admin
portals.

`step.sso_auth_provider_describe` returns descriptor JSON compatible with
`workflow-plugin-auth`'s `step.auth_provider_catalog`. It covers generic OIDC,
Okta issuer helpers, Microsoft Entra ID issuer helpers, and Auth0 issuer
helpers. Provider management remains in provider-specific plugins; this plugin
owns only OIDC runtime behavior.

## Provider configuration — `sso.oidc` module

```yaml
modules:
  - name: verifier
    type: sso.oidc
    config:
      providers:
        # Standard OIDC discovery (human login, external IDP)
        - name: okta
          type: okta
          domain: dev-12345.okta.com
          clientId: ${OKTA_CLIENT_ID}
          clientSecret: ${OKTA_CLIENT_SECRET}

        # JWKS-URI verify-only mode (cross-service / asymmetric M2M)
        # Use when the issuer publishes a /oauth/jwks endpoint but does NOT
        # implement OIDC discovery (e.g. auth.m2m ES256 issuer).
        - name: app-a
          issuer: http://app-a:8080          # must byte-match the token's iss claim
          jwksUri: http://app-a:8080/oauth/jwks
          clientId: app-b                    # validates aud claim; omit to skip aud check
          signingAlgorithms: [ES256]         # defaults to [ES256, RS256] when omitted
```

### `jwksUri` verify-only mode

| Field | Required | Default | Notes |
|---|---|---|---|
| `issuer` | yes | — | Must byte-match the `iss` claim in incoming tokens |
| `jwksUri` | yes (to activate this mode) | — | Remote JWKS endpoint URL |
| `clientId` | no | — | Validates `aud` claim; leave empty to skip audience check |
| `signingAlgorithms` | no | `[ES256, RS256]` | Algorithms accepted by the verifier |

When `jwksUri` is set, OIDC discovery (`/.well-known/openid-configuration`) is
**not** contacted. This is the correct approach for verifying tokens issued by
`auth.m2m` (or any service that publishes a JWKS endpoint without implementing
full OIDC discovery). OAuth exchange/refresh endpoints are not available in this
mode (it is verify-only by design).

The `signingAlgorithms` default includes `ES256` explicitly because
`go-oidc v3.12.0 NewVerifier` defaults to RS256-only when the list is empty,
which would silently reject ES256 tokens at runtime.
