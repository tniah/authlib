package ropc

import (
	"github.com/stretchr/testify/assert"
	"github.com/tniah/authlib/mocks/rfc6749/ropc"
	"github.com/tniah/authlib/types"
	"net/http"
	"testing"
)

func TestConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := NewConfig()
		assert.Equal(t, []string{http.MethodPost}, cfg.tokenEndpointHttpMethods)
		assert.NotNil(t, cfg.tokenReqValidators)
		assert.NotNil(t, cfg.tokenProcessors)
		assert.Equal(t, map[types.ClientAuthMethod]bool{types.ClientBasicAuthentication: true}, cfg.supportedClientAuthMethods)
		assert.Nil(t, cfg.clientMgr)
		assert.Nil(t, cfg.userMgr)
		assert.Nil(t, cfg.tokenMgr)

		cfg.SetClientManager(ropc.NewMockClientManager(t))
		assert.NotNil(t, cfg.clientMgr)

		cfg.SetUserManager(ropc.NewMockUserManager(t))
		assert.NotNil(t, cfg.userMgr)

		cfg.SetTokenManager(ropc.NewMockTokenManager(t))
		assert.NotNil(t, cfg.tokenMgr)

		cfg.SetSupportedClientAuthMethods(map[types.ClientAuthMethod]bool{types.ClientNoneAuthentication: true})
		assert.Equal(t, map[types.ClientAuthMethod]bool{types.ClientNoneAuthentication: true}, cfg.supportedClientAuthMethods)

		cfg.SetTokenEndpointHttpMethods([]string{http.MethodPut})
		assert.Equal(t, []string{http.MethodPut}, cfg.tokenEndpointHttpMethods)

		cfg.RegisterExtension(ropc.NewMockTokenRequestValidator(t))
		cfg.RegisterExtension(ropc.NewMockTokenProcessor(t))
		assert.NotNil(t, cfg.tokenReqValidators)
		assert.NotNil(t, cfg.tokenProcessors)
	})

	t.Run("validation_success", func(t *testing.T) {
		cfg := NewConfig()
		cfg.SetClientManager(ropc.NewMockClientManager(t))
		cfg.SetUserManager(ropc.NewMockUserManager(t))
		cfg.SetTokenManager(ropc.NewMockTokenManager(t))
		err := cfg.ValidateConfig()
		assert.NoError(t, err)
	})

	t.Run("validation_failed", func(t *testing.T) {
		cfg := NewConfig()
		err := cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrNilClientManager)

		cfg.SetClientManager(ropc.NewMockClientManager(t))
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrNilUserManager)

		cfg.SetUserManager(ropc.NewMockUserManager(t))
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrNilTokenManager)

		cfg.SetTokenManager(ropc.NewMockTokenManager(t))
		cfg.SetSupportedClientAuthMethods(nil)
		err = cfg.ValidateConfig()
		assert.ErrorIs(t, err, ErrEmptyClientAuthMethods)
	})
}
