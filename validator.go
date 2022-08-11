package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// ValidatorJWT validates given tokens.
type ValidatorJWT struct {
	publicKey []byte
}

// NewValidatorJWT returns a new JWT validator.
func NewValidatorJWT(publicKey []byte) *ValidatorJWT {
	jwt.TimeFunc = time.Now().UTC

	return &ValidatorJWT{
		publicKey: publicKey,
	}
}

var (
	// ErrTokenInvalid is returned if a given token is considered invalid by the JWT Validator.
	ErrTokenInvalid = errors.New("token is invalid")
)

// Validate will validate a given token to check it has the correct
// signature, hasn't expired and and was created/signed by the sentinel.
//
// It will also check that the audience claim matches the given one.
// Audience claim is case insensitive
func (j *ValidatorJWT) ValidateForAudience(token, aud string) error {
	_, err := j.validate(token, &aud)
	return err
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

	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
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

	caud, _ := claims["aud"].(string)
	ciss, _ := claims["iss"].(string)
	csub, _ := claims["sub"].(string)
	isstype, _ := claims[CustomClaimIssuerType].(string)

	return &ClaimData{
		Audience:   caud,
		Issuer:     ciss,
		IssuerType: isstype,
		Subject:    csub,
	}, nil
}

// ValidationKey returns a public key which is being used to validate tokens.
func (j *ValidatorJWT) ValidationKey() []byte {
	return j.publicKey
}
