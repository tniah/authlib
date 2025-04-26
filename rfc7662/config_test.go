package rfc7662

import (
	"github.com/stretchr/testify/assert"
	mock "github.com/tniah/authlib/mocks/rfc7662"
	"github.com/tniah/authlib/types"
	"testing"
)

func TestConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := NewConfig()
		expected := Config{
			endpointName:  "test-endpoint-name",
			clientManager: mock.NewMockClientManager(t),
			tokenManager:  mock.NewMockTokenManager(t),
			supportedClientAuthMethods: map[types.ClientAuthMethod]bool{
				types.ClientBasicAuthentication: true,
				types.ClientPostAuthentication:  true,
			},
		}

		cfg.SetEndpointName(expected.endpointName)
		cfg.SetClientManager(expected.clientManager)
		cfg.SetTokenManager(expected.tokenManager)

		assert.Equal(t, expected.endpointName, cfg.endpointName)
		assert.NotNil(t, cfg.clientManager)
		assert.NotNil(t, cfg.tokenManager)
	})

	t.Run("error", func(t *testing.T) {
		cfg := NewConfig()
		cfg.SetEndpointName("")
		err := cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrEmptyEndpointName)

		cfg.SetEndpointName("test")
		cfg.SetClientManager(nil)
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrNilClientManager)

		cfg.SetClientManager(mock.NewMockClientManager(t))
		cfg.SetTokenManager(nil)
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrNilTokenManager)
	})
}
