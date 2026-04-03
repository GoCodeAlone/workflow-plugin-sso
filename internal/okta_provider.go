package internal

import "fmt"

// OktaIssuer returns the OIDC issuer URL for an Okta organization.
func OktaIssuer(domain, authServerID string) string {
	if domain == "" {
		return ""
	}
	if authServerID == "" {
		authServerID = "default"
	}
	return fmt.Sprintf("https://%s/oauth2/%s", domain, authServerID)
}

// OktaDefaultClaimMapping returns claim paths typical for Okta tokens.
func OktaDefaultClaimMapping() ClaimMapping {
	return ClaimMapping{
		Roles:  "groups",
		Groups: "groups",
		Email:  "email",
		Name:   "name",
	}
}
