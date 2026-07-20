package requests

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/types"
)

func TestNewAuthorizationRequestFromHttp(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/?response_type=code&client_id=myclient&redirect_uri=https://example.com/cb&scope=openid+email&state=xyz&max_age=300", nil)
		req, err := NewAuthorizationRequestFromHttp(r)
		assert.NoError(t, err)
		assert.Equal(t, types.ResponseTypeCode, req.ResponseType)
		assert.Equal(t, "myclient", req.ClientID)
		assert.Equal(t, "https://example.com/cb", req.RedirectURI)
		assert.Contains(t, req.Scopes.String(), "openid")
		assert.Contains(t, req.Scopes.String(), "email")
		assert.Equal(t, "xyz", req.State)
		assert.Equal(t, types.NewMaxAge(300), req.MaxAge)
	})

	t.Run("invalid max_age returns error", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/?max_age=abc", nil)
		req, err := NewAuthorizationRequestFromHttp(r)
		authErr := autherrors.ToAuthLibError(err)
		assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)
		assert.Nil(t, req)
	})
}

func TestAuthorizationRequest_ValidateResponseType(t *testing.T) {
	req := &AuthorizationRequest{}
	err := req.ValidateResponseType()
	authErr := autherrors.ToAuthLibError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	req.ResponseType = types.ResponseTypeCode
	assert.NoError(t, req.ValidateResponseType())

	// optional when false is passed
	empty := &AuthorizationRequest{}
	assert.NoError(t, empty.ValidateResponseType(false))
}

func TestAuthorizationRequest_ValidateClientID(t *testing.T) {
	req := &AuthorizationRequest{}
	err := req.ValidateClientID()
	authErr := autherrors.ToAuthLibError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	assert.NoError(t, req.ValidateClientID(false))

	req.ClientID = "myclient"
	assert.NoError(t, req.ValidateClientID())
}

func TestAuthorizationRequest_ValidateRedirectURI(t *testing.T) {
	req := &AuthorizationRequest{}
	err := req.ValidateRedirectURI()
	authErr := autherrors.ToAuthLibError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	assert.NoError(t, req.ValidateRedirectURI(false))

	req.RedirectURI = "https://example.com/cb"
	assert.NoError(t, req.ValidateRedirectURI())
}

func TestAuthorizationRequest_CheckNonce(t *testing.T) {
	req := &AuthorizationRequest{}

	// required by default
	err := req.CheckNonce()
	authErr := autherrors.ToAuthLibError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	// optional when false is passed
	assert.NoError(t, req.CheckNonce(false))

	req.Nonce = "mynonce"
	assert.NoError(t, req.CheckNonce())
}
