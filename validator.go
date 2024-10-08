package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// ValidatorJWT validates given tokens.
type ValidatorJWT struct {
	publicKey []byte
}

// NewValidatorJWT returns a new JWT validator.
func NewValidatorJWT(publicKey []byte) *ValidatorJWT {
	jwt.TimeFunc = func() time.Time {
		return time.Now().UTC()
	}

	return &ValidatorJWT{
		publicKey: publicKey,
	}
}

var (
	// ErrTokenInvalid is returned if a given token is considered invalid by the JWT Validator.
	ErrTokenInvalid = errors.New("token is invalid")
)

// ValidateForAudience will validate a given token to check it has the correct
// signature, hasn't expired and and was created/signed by the sentinel.
//
// It will also check that the audience claim matches the given one.
// Audience claim is case insensitive
func (j *ValidatorJWT) ValidateForAudience(token, aud string) error {
	_, err := j.validate(token, &aud)
	return err
}

// ValidateForAudienceExtract will validate a given token to check it has the correct
// signature, hasn't expired and and was created/signed by the sentinel.
//
// It will also check that the audience claim matches the given one.
// Audience claim is case insensitive
//
// It will also pull data which the caller can use for additional validation
// or user data lookup.
func (j *ValidatorJWT) ValidateForAudienceExtract(token, aud string) (*ClaimData, error) {
	return j.validate(token, &aud)
}

// Validate will validate a given token to check it has the correct
// signature, hasn't expired and and was created/signed by the sentinel.
func (j *ValidatorJWT) Validate(token string) error {
	_, err := j.validate(token, nil)
	return err
}

// ValidateExtract will validate a given token to check it has the correct
// signature, hasn't expired and and was created/signed by the sentinel.
//
// It will also pull data which the caller can use for additional validation
// or user data lookup.
func (j *ValidatorJWT) ValidateExtract(token string) (*ClaimData, error) {
	return j.validate(token, nil)
}

func (j *ValidatorJWT) validate(token string, aud *string) (*ClaimData, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)
	if err != nil {
		return nil, fmt.Errorf("validate: parse key: %w", err)
	}

	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (any, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method %q: %w", jwtToken.Header["alg"], ErrTokenInvalid)
		}

		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, ErrTokenInvalid
	}

	if !claims.VerifyIssuer(IssuerName, true) {
		return nil, fmt.Errorf("unknown issuer: %w", ErrTokenInvalid)
	}

	if aud != nil && !claims.VerifyAudience(*aud, true) {
		return nil, fmt.Errorf("audience missmatch: %w", ErrTokenInvalid)
	}

	caud := make([]string, 0)
	for _, c := range claims["aud"].([]any) {
		caud = append(caud, c.(string))
	}
	ciss, _ := claims["iss"].(string)
	csub, _ := claims["sub"].(string)
	attr, _ := claims["attr"].(string)
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	jti, _ := claims["jti"].(string)
	username, _ := claims["username"].(string)
	isst, _ := claims[CustomClaimIssuerType].(string)

	return &ClaimData{
		Audience:   caud,
		Issuer:     ciss,
		IssuerType: isst,
		Subject:    csub,
		ExpiresAt:  exp,
		Attributes: attr,
		ID:         jti,
		IssuedAt:   iat,
		Username:   username,
	}, nil
}

// ValidationKey returns a public key which is being used to validate tokens.
func (j *ValidatorJWT) ValidationKey() []byte {
	return j.publicKey
}
