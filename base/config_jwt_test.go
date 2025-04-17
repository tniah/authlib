package base

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	mock "github.com/tniah/authlib/mocks/base"
	"testing"
	"time"
)

func TestJWTConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := &JWTConfig{}
		expected := &JWTConfig{
			issuer:              "https://example.com/",
			issuerGenerator:     mock.NewMockIssuerGenerator(t).Execute,
			expiresIn:           time.Minute * 60 * 24,
			expiresInGenerator:  mock.NewMockExpiresInGenerator(t).Execute,
			signingKey:          []byte("my-secret-key"),
			signingKeyMethod:    jwt.SigningMethodHS256,
			signingKeyID:        "my-key-id",
			signingKeyGenerator: mock.NewMockSigningKeyGenerator(t).Execute,
			extraClaimGenerator: mock.NewMockExtraClaimGenerator(t).Execute,
		}

		cfg.SetIssuer(expected.issuer)
		cfg.SetIssuerGenerator(expected.issuerGenerator)
		cfg.SetExpiresIn(expected.expiresIn)
		cfg.SetExpiresInGenerator(expected.expiresInGenerator)
		cfg.SetSigningKey(expected.signingKey, expected.signingKeyMethod, expected.signingKeyID)
		cfg.SetSigningKeyGenerator(expected.signingKeyGenerator)
		cfg.SetExtraClaimGenerator(expected.extraClaimGenerator)

		assert.Equal(t, expected.issuer, cfg.issuer)
		assert.NotNil(t, cfg.issuerGenerator)
		assert.Equal(t, expected.expiresIn, cfg.expiresIn)
		assert.NotNil(t, cfg.expiresInGenerator)
		assert.Equal(t, expected.signingKey, cfg.signingKey)
		assert.Equal(t, expected.signingKeyMethod, cfg.signingKeyMethod)
		assert.Equal(t, expected.signingKeyID, cfg.signingKeyID)
		assert.NotNil(t, cfg.signingKeyGenerator)
		assert.NotNil(t, cfg.extraClaimGenerator)
	})

	t.Run("error", func(t *testing.T) {
		cfg := &JWTConfig{}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrMissingIssuer)

		cfg.SetIssuer("https://example.com/")
		cfg.SetExpiresIn(0)
		err = cfg.Validate()
		assert.ErrorIs(t, err, ErrMissingExpiresIn)

		cfg.SetExpiresIn(time.Second * 3600)
		err = cfg.Validate()
		assert.ErrorIs(t, err, ErrMissingSigningKey)

		cfg.SetSigningKey([]byte("my-secret-key"), nil)
		err = cfg.Validate()
		assert.ErrorIs(t, err, ErrMissingSigningKeyMethod)
	})
}
