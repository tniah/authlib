package rfc7662

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/mocks/models"
	"github.com/tniah/authlib/mocks/rfc7662"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTokenIntrospection(t *testing.T) {
	cfg := NewIntrospectionConfig()
	h := NewTokenIntrospection(cfg)

	mockClient := models.NewMockClient(t)

	mockToken := models.NewMockToken(t)
	mockToken.On("GetIssuedAt").Return(time.Now()).Once()
	mockToken.On("GetAccessTokenExpiresIn").Return(60 * time.Minute).Once()

	mockTokenMgr := rfc7662.NewMockTokenManager(t)
	expected := map[string]interface{}{
		"active":   true,
		"iss":      "https://server.example.com/",
		"scope":    "read write dolphin",
		"username": "makai",
	}
	mockTokenMgr.On("QueryByToken", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(mockToken, nil).Once()
	mockTokenMgr.On("Inspect", mock.Anything, mock.Anything).Return(expected).Once()
	cfg.SetTokenManager(mockTokenMgr)

	mockClientMgr := rfc7662.NewMockClientManager(t)
	mockClientMgr.On("Authenticate", mock.AnythingOfType("*http.Request"), mock.AnythingOfType("map[string]bool"), mock.AnythingOfType("string")).Return(mockClient, nil).Once()
	mockClientMgr.On("CheckPermission", mock.Anything, mock.Anything, mock.AnythingOfType("*http.Request")).Return(true).Once()
	cfg.SetClientManager(mockClientMgr)

	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	err := h.EndpointResponse(r, rw)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rw.Code)

	mockClient.AssertExpectations(t)
	mockToken.AssertExpectations(t)
	mockTokenMgr.AssertExpectations(t)
	mockClientMgr.AssertExpectations(t)
}

func TestCheckEndpoint(t *testing.T) {
	cfg := NewIntrospectionConfig().SetEndpointName(EndpointNameTokenIntrospection)
	h := NewTokenIntrospection(cfg)
	cases := []struct {
		name     string
		expected bool
	}{
		{
			"my-endpoint",
			false,
		},
		{
			EndpointNameTokenIntrospection,
			true,
		},
	}
	for i, test := range cases {
		ret := h.CheckEndpoint(test.name)
		assert.Equalf(t, test.expected, ret, "case %d failed", i)
	}
}

func TestAuthenticateToken(t *testing.T) {
	cfg := NewIntrospectionConfig()
	h := NewTokenIntrospection(cfg)

	mockClient := models.NewMockClient(t)
	mockToken := models.NewMockToken(t)
	mockTokenMgr := rfc7662.NewMockTokenManager(t)
	cfg.SetTokenManager(mockTokenMgr)

	mockClientMgr := rfc7662.NewMockClientManager(t)
	cfg.SetClientManager(mockClientMgr)

	t.Run("success", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r := NewIntrospectionRequestFromHTTP(hr)

		mockTokenMgr.On("QueryByToken", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(mockToken, nil).Once()
		mockClientMgr.On("CheckPermission", mock.Anything, mock.Anything, mock.AnythingOfType("*http.Request")).Return(true).Once()

		r.Client = mockClient
		err := h.authenticateToken(r)
		assert.NoError(t, err)

		mockToken.AssertExpectations(t)
	})

	t.Run("error_when_client_have_no_permission", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r := NewIntrospectionRequestFromHTTP(hr)

		mockTokenMgr.On("QueryByToken", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(mockToken, nil).Once()
		mockClientMgr.On("CheckPermission", mock.Anything, mock.Anything, mock.AnythingOfType("*http.Request")).Return(false).Once()
		r.Client = mockClient

		err := h.authenticateToken(r)
		authErr, err := autherrors.ToAuthLibError(err)
		assert.NoError(t, err)
		assert.Equal(t, "client does not have permission to inspect token", authErr.Description)

		mockToken.AssertExpectations(t)
	})
}

func TestCheckParams(t *testing.T) {
	h := NewTokenIntrospection(NewIntrospectionConfig())

	t.Run("success", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r := NewIntrospectionRequestFromHTTP(hr)
		err := h.checkParams(r)
		assert.NoError(t, err)
	})

	t.Run("error_when_http_method_is_disallowed", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodGet, "/", nil)
		r := NewIntrospectionRequestFromHTTP(hr)
		err := h.checkParams(r)
		authErr, err := autherrors.ToAuthLibError(err)
		assert.NoError(t, err)
		assert.Equal(t, "request must be \"POST\"", authErr.Description)
	})

	t.Run("error_when_content_type_is_invalid", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
		r := NewIntrospectionRequestFromHTTP(hr)
		err := h.checkParams(r)
		authErr, err := autherrors.ToAuthLibError(err)
		assert.NoError(t, err)
		assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)
	})

	t.Run("error_when_media_type_is_not_supported", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{\"token\":\"my-token\"}"))
		hr.Header.Set("Content-Type", "application/json")
		r := NewIntrospectionRequestFromHTTP(hr)
		err := h.checkParams(r)
		authErr, err := autherrors.ToAuthLibError(err)
		assert.NoError(t, err)
		assert.Equal(t, "content type must be \"application/x-www-form-urlencoded\"", authErr.Description)
	})

	t.Run("error_when_token_hint_is_invalid", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=my-hint"))
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r := NewIntrospectionRequestFromHTTP(hr)
		err := h.checkParams(r)
		authErr, err := autherrors.ToAuthLibError(err)
		assert.NoError(t, err)
		assert.Equal(t, "token type hint must be set to \"access_token\" or \"refresh_token\"", authErr.Description)
	})
}

func TestIntrospectionPayload(t *testing.T) {
	cfg := NewIntrospectionConfig()
	h := NewTokenIntrospection(cfg)
	mockToken := models.NewMockToken(t)
	mockClient := models.NewMockClient(t)
	mockTokenMgr := rfc7662.NewMockTokenManager(t)
	cfg.SetTokenManager(mockTokenMgr)

	t.Run("success", func(t *testing.T) {
		expected := map[string]interface{}{
			"active":   true,
			"iss":      "https://server.example.com/",
			"scope":    "read write dolphin",
			"username": "makai",
		}
		mockToken.On("GetIssuedAt").Return(time.Now()).Once()
		mockToken.On("GetAccessTokenExpiresIn").Return(60 * time.Minute).Once()
		mockTokenMgr.On("Inspect", mock.Anything, mock.Anything).Return(expected).Once()

		r := &IntrospectionRequest{}
		r.Tok = mockToken
		r.Client = mockClient

		payload := h.introspectionPayload(r)
		assert.Equal(t, expected, payload)

		mockToken.AssertExpectations(t)
		mockTokenMgr.AssertExpectations(t)
	})

	t.Run("error_when_token_is_invalid", func(t *testing.T) {
		r := &IntrospectionRequest{}
		r.Client = mockClient

		payload := h.introspectionPayload(r)
		assert.Equal(t, false, payload["active"])

		mockToken.On("GetIssuedAt").Return(time.Now().Add(-60 * time.Hour)).Once()
		mockToken.On("GetAccessTokenExpiresIn").Return(0 * time.Minute).Once()
		r.Tok = mockToken
		payload = h.introspectionPayload(r)
		assert.Equal(t, false, payload["active"])

		mockToken.AssertExpectations(t)
	})
}
