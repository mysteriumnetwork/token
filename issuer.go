package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
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

const (
	CustomClaimIssuerType = "isst"
)

// Issue will issue a new JWT token setting given parameters inside the claims.
func (j *IssuerJWT) Issue(sub string, aud []string, issuertype string, ttl time.Duration, attr string) (string, error) {
	if sub == "" || len(aud) < 1 || issuertype == "" {
		return "", errors.New("'sub', 'aud', 'issuertype' claims must be set")
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	now := jwt.TimeFunc()
	id := uuid.New()
	claims := jwt.MapClaims{
		"exp":                 now.Add(ttl).Unix(),
		"iat":                 now.Unix(),
		"nbf":                 now.Unix(),
		"iss":                 IssuerName,
		"aud":                 aud,
		"sub":                 sub,
		"attr":                attr,
		"jti":                 id.String(),
		CustomClaimIssuerType: issuertype,
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}
