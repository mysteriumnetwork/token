package token

import "strings"

// JWT wraps both an issuer and validator inside
// a single object for easier handling.
type JWT struct {
	*ValidatorJWT
	*IssuerJWT
}

// NewJWT returns a new JWT object.
func NewJWT(v *ValidatorJWT, i *IssuerJWT) *JWT {
	return &JWT{
		ValidatorJWT: v,
		IssuerJWT:    i,
	}
}

// ClaimData can be retrieved from a token for further verification.
type ClaimData struct {
	IssuerType string
	Issuer     string
	Audience   string
	Subject    string
}

// ParsedAudience will parse audience into a string map.
func (c *ClaimData) ParsedAudience() []string {
	return strings.Split(c.Audience, ",")
}
