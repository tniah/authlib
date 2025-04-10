package rfc9068

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	mock "github.com/tniah/authlib/mocks/rfc9068"
	"testing"
	"time"
)

func TestGeneratorOptions(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		opts := NewJWTAccessTokenGeneratorOptions()
		expected := &GeneratorOptions{
			issuer:              "https://example.com/",
			issuerGenerator:     mock.NewMockIssuerGenerator(t).Execute,
			expiresIn:           time.Minute * 60 * 24,
			expiresInGenerator:  mock.NewMockExpiresInGenerator(t).Execute,
			signingKey:          []byte("my-secret-key"),
			signingKeyMethod:    jwt.SigningMethodHS256,
			signingKeyID:        "my-key-id",
			signingKeyGenerator: mock.NewMockSigningKeyGenerator(t).Execute,
			extraClaimGenerator: mock.NewMockExtraClaimGenerator(t).Execute,
			jwtIDGenerator:      mock.NewMockJWTIDGenerator(t).Execute,
		}

		opts.SetIssuer(expected.issuer)
		opts.SetIssuerGenerator(expected.issuerGenerator)
		opts.SetExpiresIn(expected.expiresIn)
		opts.SetExpiresInGenerator(expected.expiresInGenerator)
		opts.SetSigningKey(expected.signingKey, expected.signingKeyMethod, expected.signingKeyID)
		opts.SetSigningKeyGenerator(expected.signingKeyGenerator)
		opts.SetExtraClaimGenerator(expected.extraClaimGenerator)
		opts.SetJWTIDGenerator(expected.jwtIDGenerator)

		assert.Equal(t, expected.issuer, opts.issuer)
		assert.NotNil(t, opts.issuerGenerator)
		assert.Equal(t, expected.expiresIn, opts.expiresIn)
		assert.NotNil(t, opts.expiresInGenerator)
		assert.Equal(t, expected.signingKey, opts.signingKey)
		assert.Equal(t, expected.signingKeyMethod, opts.signingKeyMethod)
		assert.Equal(t, expected.signingKeyID, opts.signingKeyID)
		assert.NotNil(t, opts.signingKeyGenerator)
		assert.NotNil(t, opts.extraClaimGenerator)
		assert.NotNil(t, opts.jwtIDGenerator)
	})

	t.Run("error", func(t *testing.T) {
		opts := NewJWTAccessTokenGeneratorOptions()
		err := opts.Validate()
		assert.ErrorIs(t, err, ErrMissingIssuer)

		opts.SetIssuer("https://example.com/")
		opts.SetExpiresIn(0)
		err = opts.Validate()
		assert.ErrorIs(t, err, ErrMissingExpiresIn)

		opts.SetExpiresIn(time.Second * 3600)
		err = opts.Validate()
		assert.ErrorIs(t, err, ErrMissingSigningKey)

		opts.SetSigningKey([]byte("my-secret-key"), nil)
		err = opts.Validate()
		assert.ErrorIs(t, err, ErrMissingSigningKeyMethod)
	})
}
