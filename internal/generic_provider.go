package internal

// GenericDefaultClaimMapping returns standard OIDC claim paths.
func GenericDefaultClaimMapping() ClaimMapping {
	return ClaimMapping{
		Roles:  "roles",
		Groups: "groups",
		Email:  "email",
		Name:   "name",
	}
}
