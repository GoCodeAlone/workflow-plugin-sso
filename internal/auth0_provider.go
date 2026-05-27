package internal

import (
	"net/url"
	"strings"
)

// Auth0Issuer returns the OIDC issuer URL for an Auth0 tenant domain.
func Auth0Issuer(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if !strings.Contains(domain, "://") {
		domain = "https://" + domain
	}
	parsed, err := url.Parse(domain)
	if err != nil || parsed.Host == "" {
		return ""
	}
	parsed.Path = "/"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func Auth0DefaultClaimMapping() ClaimMapping {
	return ClaimMapping{
		Roles:  "https://workflow.dev/roles",
		Groups: "https://workflow.dev/groups",
		Email:  "email",
		Name:   "name",
	}
}
