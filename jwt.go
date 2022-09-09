package token

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
	IssuedAt   float64
	Audience   []string
	Subject    string
	ExpiresAt  float64
	Attributes string
	ID         string
}
