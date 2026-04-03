package internal

import "fmt"

// EntraIssuer returns the OIDC issuer URL for a Microsoft Entra ID (Azure AD) tenant.
func EntraIssuer(tenantID string) string {
	if tenantID == "" {
		return ""
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
}

// EntraDefaultClaimMapping returns claim paths typical for Entra ID tokens.
func EntraDefaultClaimMapping() ClaimMapping {
	return ClaimMapping{
		Roles:  "roles",
		Groups: "groups",
		Email:  "email",
		Name:   "name",
	}
}
