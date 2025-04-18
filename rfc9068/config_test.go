package rfc9068

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/tniah/authlib/mocks/rfc9068"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := NewGeneratorConfig()
		assert.Equal(t, DefaultExpiresIn, cfg.expiresIn)

		cfg.SetIssuer("https://example.com")
		assert.Equal(t, "https://example.com", cfg.issuer)

		issGen := rfc9068.NewMockIssuerGenerator(t).Execute
		cfg.SetIssuerGenerator(issGen)
		assert.NotNil(t, cfg.issuerGenerator)

		cfg.SetExpiresIn(time.Second * 60)
		assert.Equal(t, time.Second*60, cfg.expiresIn)

		expGen := rfc9068.NewMockExpiresInGenerator(t).Execute
		cfg.SetExpiresInGenerator(expGen)
		assert.NotNil(t, cfg.expiresInGenerator)

		cfg.SetSigningKey([]byte("test"), jwt.SigningMethodHS256, "my-kid")
		assert.Equal(t, []byte("test"), cfg.signingKey)
		assert.Equal(t, jwt.SigningMethodHS256, cfg.signingKeyMethod)
		assert.Equal(t, "my-kid", cfg.signingKeyID)

		extraGen := rfc9068.NewMockExtraClaimGenerator(t).Execute
		cfg.SetExtraClaimGenerator(extraGen)
		assert.NotNil(t, cfg.extraClaimGenerator)

		jwtIDGen := rfc9068.NewMockJWTIDGenerator(t).Execute
		cfg.SetJWTIDGenerator(jwtIDGen)
		assert.NotNil(t, cfg.jwtIDGenerator)
	})

	t.Run("error", func(t *testing.T) {
		cfg := NewGeneratorConfig()
		err := cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrMissingIssuer)

		issGen := rfc9068.NewMockIssuerGenerator(t).Execute
		cfg.SetIssuerGenerator(issGen)
		cfg.SetExpiresIn(0)
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrMissingExpiresIn)

		cfg.SetExpiresIn(time.Second * 60)
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrMissingSigningKey)

		cfg.SetSigningKey([]byte("test"), nil)
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrMissingSigningKeyMethod)
	})
}
