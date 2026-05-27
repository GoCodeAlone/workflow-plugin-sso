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
