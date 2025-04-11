package rfc7662

import (
	"github.com/stretchr/testify/assert"
	mock "github.com/tniah/authlib/mocks/rfc7662"
	"testing"
)

func TestIntrospectionConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := NewIntrospectionConfig()
		expected := IntrospectionConfig{
			endpointName:  "test-endpoint-name",
			clientManager: mock.NewMockClientManager(t),
			tokenManager:  mock.NewMockTokenManager(t),
			clientAuthMethods: map[string]bool{
				"client_secret_basic": true,
				"client_secret_post":  true,
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
		cfg := NewIntrospectionConfig()
		cfg.SetEndpointName("")
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrEmptyEndpointName)

		cfg.SetEndpointName("test")
		cfg.SetClientManager(nil)
		err = cfg.Validate()
		assert.ErrorIs(t, err, ErrNilClientManager)

		cfg.SetClientManager(mock.NewMockClientManager(t))
		cfg.SetTokenManager(nil)
		err = cfg.Validate()
		assert.ErrorIs(t, err, ErrNilTokenManager)
	})
}
