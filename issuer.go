package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// IssuerJWT issues JWT tokens.
type IssuerJWT struct {
	privateKey []byte
}

// IssuerName is the expected name of the issuer for any token
// issued by sentinel.
const IssuerName = "myst-sentinel"

// NewIssuerJWT returns a new IssuerJWT object.
func NewIssuerJWT(privateKey []byte) *IssuerJWT {
	jwt.TimeFunc = func() time.Time {
		return time.Now().UTC()
	}

	return &IssuerJWT{
		privateKey: privateKey,
	}
}

type CustomClaim string

const (
	CustomClaimIssuerType = "isst"
)

// Issue will issue a new JWT token setting given parameters inside the claims.
func (j *IssuerJWT) Issue(sub, aud, issuertype string, ttl time.Duration, attr string) (string, error) {
	if sub == "" || aud == "" || issuertype == "" {
		return "", errors.New("'sub', 'aud', 'issuertype' claims must be set")
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	now := jwt.TimeFunc()
	claims := jwt.MapClaims{
		"exp":                 now.Add(ttl).Unix(),
		"iat":                 now.Unix(),
		"nbf":                 now.Unix(),
		"iss":                 IssuerName,
		"aud":                 aud,
		"sub":                 sub,
		"attr":                attr,
		CustomClaimIssuerType: issuertype,
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}
