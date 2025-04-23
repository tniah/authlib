package clientauth

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tniah/authlib/mocks/models"
	rfc6749 "github.com/tniah/authlib/mocks/rfc6749/client_authentication"
	"github.com/tniah/authlib/types"
	"net/http/httptest"
	"testing"
)

func TestManager_New(t *testing.T) {
	m := NewManager()
	assert.NotNil(t, m.handlers)
}

func TestManager_Register(t *testing.T) {
	m := &Manager{}

	mockHandler := rfc6749.NewMockHandler(t)
	mockHandler.On("Method").Return(types.ClientBasicAuthentication).Once()
	m.Register(mockHandler)

	h, ok := m.handlers[types.ClientBasicAuthentication.String()]
	assert.True(t, ok)
	assert.Equal(t, mockHandler, h)

	mockHandler.AssertExpectations(t)
}

func TestManager_Authenticate(t *testing.T) {
	m := NewManager()

	mockHandler := rfc6749.NewMockHandler(t)
	mockHandler.On("Method").Return(types.ClientBasicAuthentication).Once()
	m.Register(mockHandler)

	r := httptest.NewRequest("POST", "/", nil)
	t.Run("success", func(t *testing.T) {
		mockClient := models.NewMockClient(t)
		mockClient.On("CheckTokenEndpointAuthMethod", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(true).Once()

		mockHandler.On("Authenticate", mock.AnythingOfType("*http.Request")).Return(mockClient, nil).Once()

		c, err := m.Authenticate(r, map[string]bool{types.ClientBasicAuthentication.String(): true}, "token")
		assert.NoError(t, err)
		assert.Equal(t, mockClient, c)

		mockClient.AssertExpectations(t)
		mockHandler.AssertExpectations(t)
	})

	t.Run("error_when_method_is_not_supported", func(t *testing.T) {
		c, err := m.Authenticate(r, map[string]bool{"password": true}, "token")
		assert.ErrorIs(t, err, ErrInvalidClient)
		assert.Nil(t, c)
	})

	t.Run("error_when_method_is_not_supported_by_client", func(t *testing.T) {
		mockClient := models.NewMockClient(t)
		mockClient.On("CheckTokenEndpointAuthMethod", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(false).Once()

		mockHandler.On("Authenticate", mock.AnythingOfType("*http.Request")).Return(mockClient, nil).Once()

		c, err := m.Authenticate(r, map[string]bool{types.ClientBasicAuthentication.String(): true}, "token")
		assert.Nil(t, c)
		assert.ErrorIs(t, err, ErrInvalidClient)

		mockClient.AssertExpectations(t)
		mockHandler.AssertExpectations(t)
	})
}
