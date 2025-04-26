package ropc

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tniah/authlib/integrations/sql"
	"github.com/tniah/authlib/mocks/rfc6749/ropc"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFlow_Must(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockClientMgr := ropc.NewMockClientManager(t)
		mockUserMgr := ropc.NewMockUserManager(t)
		mockTokMgr := ropc.NewMockTokenManager(t)

		f, err := Must(NewConfig().SetClientManager(mockClientMgr).SetUserManager(mockUserMgr).SetTokenManager(mockTokMgr))
		require.NoError(t, err)
		assert.NotNil(t, f)
	})

	t.Run("error", func(t *testing.T) {
		f, err := Must(NewConfig().SetClientManager(nil))
		require.Error(t, err)
		assert.Nil(t, f)
	})
}

func TestFlow_CheckGrantType(t *testing.T) {
	f := New(NewConfig())
	cases := []struct {
		grantType types.GrantType
		expected  bool
	}{
		{
			types.GrantTypeROPC,
			true,
		},
		{
			types.NewGrantType(""),
			false,
		},
		{
			types.NewGrantType("test"),
			false,
		},
	}

	for i, c := range cases {
		valid := f.CheckGrantType(c.grantType)
		assert.Equalf(t, c.expected, valid, "case %d failed: expected=%t, actual=%t", i, c.expected, valid)
	}
}

func TestFlow_TokenResponse(t *testing.T) {
	mockToken := &sql.Token{}
	mockTokenMgr := ropc.NewMockTokenManager(t)
	mockTokenMgr.On("New").Return(mockToken).Once()
	mockTokenMgr.On("Generate", mock.AnythingOfType("*sql.Token"), mock.AnythingOfType("*requests.TokenRequest"), mock.AnythingOfType("bool")).Return(nil).Once()
	mockTokenMgr.On("Save", mock.Anything, mock.AnythingOfType("*sql.Token")).Return(nil).Once()

	f := New(NewConfig().SetTokenManager(mockTokenMgr))
	r := &requests.TokenRequest{
		GrantType: types.GrantTypeROPC,
		Username:  "makai",
		Password:  "123456",
		Client:    &sql.Client{},
		Request:   httptest.NewRequest("POST", "/oauth/token", nil),
	}

	err := f.TokenResponse(r, httptest.NewRecorder())
	assert.NoError(t, err)
}

func TestFlow_checkTokenEndpointHttpMethod(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := NewConfig().SetTokenEndpointHttpMethods([]string{http.MethodDelete, http.MethodPut})
		f := New(cfg)
		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPut, "/", nil),
		}
		err := f.checkTokenEndpointHttpMethod(r)
		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		cfg := NewConfig().SetTokenEndpointHttpMethods([]string{http.MethodDelete})
		f := New(cfg)
		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}
		err := f.checkTokenEndpointHttpMethod(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})
}

func TestFlow_ValidateGrantType(t *testing.T) {
	f := New(NewConfig())
	t.Run("success", func(t *testing.T) {
		r := &requests.TokenRequest{
			GrantType: types.GrantTypeROPC,
		}
		err := f.validateGrantType(r)
		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		reqs := []*requests.TokenRequest{
			{
				GrantType: "",
			},
			{
				GrantType: "makai",
			},
		}
		for i, r := range reqs {
			err := f.validateGrantType(r)
			assert.Errorf(t, err, "case %d failed: actual=%v", i, err)
		}
	})
}

func TestFlow_checkParams(t *testing.T) {
	f := New(NewConfig())
	t.Run("success", func(t *testing.T) {
		r := &requests.TokenRequest{
			Request:   httptest.NewRequest(http.MethodPost, "/", nil),
			GrantType: types.GrantTypeROPC,
			Username:  "makai",
			Password:  "123456",
		}
		err := f.checkParams(r)
		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {

		cases := []struct {
			r     *requests.TokenRequest
			error string
		}{
			{
				&requests.TokenRequest{
					Request: httptest.NewRequest(http.MethodDelete, "/", nil),
				},
				"invalid_request",
			},
			{
				&requests.TokenRequest{
					Request:   httptest.NewRequest(http.MethodPost, "/", nil),
					GrantType: "",
				},
				"invalid_request",
			},
			{
				&requests.TokenRequest{
					Request:   httptest.NewRequest(http.MethodPost, "/", nil),
					GrantType: types.GrantTypeAuthorizationCode,
				},
				"unsupported_grant_type",
			},
			{
				&requests.TokenRequest{
					Request:   httptest.NewRequest(http.MethodPost, "/", nil),
					GrantType: types.GrantTypeROPC,
					Username:  "",
				},
				"invalid_request",
			},
			{
				&requests.TokenRequest{
					Request:   httptest.NewRequest(http.MethodPost, "/", nil),
					GrantType: types.GrantTypeROPC,
					Username:  "makai",
					Password:  "",
				},
				"invalid_request",
			},
		}
		for i, c := range cases {
			err := f.checkParams(c.r)
			assert.Error(t, err)
			assert.Containsf(t, err.Error(), c.error, "case %d failed", i)
		}
	})
}

func TestFlow_authenticateClient(t *testing.T) {
	mockClientMgr := ropc.NewMockClientManager(t)
	f := New(NewConfig().SetClientManager(mockClientMgr))

	t.Run("success", func(t *testing.T) {
		mockClient := &sql.Client{
			GrantTypes: []string{types.GrantTypeROPC.String()},
		}
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(mockClient, nil).Once()
		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}

		err := f.authenticateClient(r)
		assert.NoError(t, err)

		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_client_authentication_failed", func(t *testing.T) {
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(nil, nil).Once()
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(nil, errors.New("unexpected")).Once()

		for i := 0; i < 2; i++ {
			r := &requests.TokenRequest{
				Request: httptest.NewRequest(http.MethodPost, "/", nil),
			}
			err := f.authenticateClient(r)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid_client")
		}

		mockClientMgr.AssertExpectations(t)
	})

	t.Run("error_when_grant_type_is_unsupported", func(t *testing.T) {
		mockClient := &sql.Client{
			GrantTypes: []string{},
		}
		mockClientMgr.On("Authenticate", mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(mockClient, nil).Once()

		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}
		err := f.authenticateClient(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized_client")

		mockClientMgr.AssertExpectations(t)
	})
}

func TestFlow_authenticateUser(t *testing.T) {
	mockUser := &sql.User{}
	mockUserMgr := ropc.NewMockUserManager(t)
	f := New(NewConfig().SetUserManager(mockUserMgr))

	t.Run("success", func(t *testing.T) {
		mockUserMgr.On("Authenticate", mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(mockUser, nil).Once()
		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
		}

		err := f.authenticateUser(r)
		assert.NoError(t, err)

		mockUserMgr.AssertExpectations(t)
	})

	t.Run("error_when_user_authentication_failed", func(t *testing.T) {
		mockUserMgr.On("Authenticate", mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil, nil).Once()
		mockUserMgr.On("Authenticate", mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil, errors.New("unexpected")).Once()

		for i := 0; i < 2; i++ {
			r := &requests.TokenRequest{
				Request: httptest.NewRequest(http.MethodPost, "/", nil),
			}
			err := f.authenticateUser(r)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid_request")
		}

		mockUserMgr.AssertExpectations(t)
	})
}

func TestFlow_genToken(t *testing.T) {
	mockToken := &sql.Token{}
	mockClient := &sql.Client{}
	mockTokenMgr := ropc.NewMockTokenManager(t)
	f := New(NewConfig().SetTokenManager(mockTokenMgr))

	t.Run("success", func(t *testing.T) {
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.AnythingOfType("bool")).Return(nil).Once()

		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
			Client:  mockClient,
		}
		tok, err := f.genToken(r)
		assert.NoError(t, err)
		assert.Equal(t, mockToken, tok)

		mockTokenMgr.AssertExpectations(t)
	})

	t.Run("error", func(t *testing.T) {
		mockTokenMgr.On("New").Return(nil).Once()
		mockTokenMgr.On("New").Return(mockToken).Once()
		mockTokenMgr.On("Generate", mock.Anything, mock.Anything, mock.AnythingOfType("bool")).Return(errors.New("unexpected")).Once()

		r := &requests.TokenRequest{
			Request: httptest.NewRequest(http.MethodPost, "/", nil),
			Client:  mockClient,
		}
		tok, err := f.genToken(r)
		assert.ErrorIs(t, err, ErrNilToken)
		assert.Nil(t, tok)

		tok, err = f.genToken(r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected")

		mockTokenMgr.AssertExpectations(t)
	})
}
