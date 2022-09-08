package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_JWT(t *testing.T) {

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	pub := key.Public()

	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	// Encode public key to PKCS#1 ASN.1 PEM.

	marshaled, err := x509.MarshalPKIXPublicKey(pub.(*rsa.PublicKey))
	require.NoError(t, err)

	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: marshaled,
		},
	)

	validator := NewValidatorJWT(pubPEM)
	issuer := NewIssuerJWT(keyPEM)

	jwt := NewJWT(validator, issuer)
	t.Run("issue and validate with no aud", func(t *testing.T) {
		aud := "pool1"
		typ := "password"
		sub := uuid.New().String()
		token, err := jwt.Issue(sub, aud, typ, time.Hour, "")
		assert.NoError(t, err)

		err = jwt.Validate(token)
		assert.NoError(t, err)
	})

	t.Run("issue and validate with aud", func(t *testing.T) {
		aud := "pool1"
		typ := "password"
		sub := uuid.New().String()
		token, err := jwt.Issue(sub, aud, typ, time.Hour, "")
		assert.NoError(t, err)

		err = jwt.ValidateForAudience(token, aud)
		assert.NoError(t, err)
	})

	t.Run("issue and extract data", func(t *testing.T) {
		aud := "pool1"
		typ := "password"
		sub := uuid.New().String()
		token, err := jwt.Issue(sub, aud, typ, time.Hour, "")
		assert.NoError(t, err)

		d, err := jwt.ValidateExtract(token)
		assert.NoError(t, err)
		assert.Equal(t, aud, d.Audience)
		assert.Equal(t, sub, d.Subject)
		assert.Equal(t, IssuerName, d.Issuer)
		assert.Equal(t, typ, d.IssuerType)
		assert.Greater(t, d.ExpiresAt, float64(time.Now().Unix()))

	})

}
