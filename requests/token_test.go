package requests

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/types"
)

func TestNewTokenRequestFromHttp(t *testing.T) {
	body := strings.NewReader("grant_type=authorization_code&code=mycode&redirect_uri=https://example.com/cb&client_id=myclient&scope=openid+email&username=alice&password=secret&code_verifier=myverifier")
	r := httptest.NewRequest("POST", "/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req := NewTokenRequestFromHttp(r)
	assert.Equal(t, types.GrantTypeAuthorizationCode, req.GrantType)
	assert.Equal(t, "mycode", req.Code)
	assert.Equal(t, "https://example.com/cb", req.RedirectURI)
	assert.Equal(t, "myclient", req.ClientID)
	assert.Contains(t, req.Scopes.String(), "openid")
	assert.Contains(t, req.Scopes.String(), "email")
	assert.Equal(t, "alice", req.Username)
	assert.Equal(t, "secret", req.Password)
	assert.Equal(t, "myverifier", req.CodeVerifier)
	assert.Equal(t, r, req.Request)
}

func TestTokenRequest_ValidateGrantType(t *testing.T) {
	req := &TokenRequest{}
	err := req.ValidateGrantType()
	authErr := autherrors.ToAuthLibError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	req.GrantType = types.GrantTypeAuthorizationCode
	assert.NoError(t, req.ValidateGrantType())
}

func TestTokenRequest_ValidateCode(t *testing.T) {
	req := &TokenRequest{}

	// required by default
	err := req.ValidateCode()
	authErr := autherrors.ToAuthLibError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	// optional when false is passed
	assert.NoError(t, req.ValidateCode(false))

	req.Code = "mycode"
	assert.NoError(t, req.ValidateCode())
}

func TestTokenRequest_ValidateRedirectURI(t *testing.T) {
	req := &TokenRequest{}

	// required by default
	err := req.ValidateRedirectURI()
	authErr := autherrors.ToAuthLibError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	// optional when false is passed
	assert.NoError(t, req.ValidateRedirectURI(false))

	req.RedirectURI = "https://example.com/cb"
	assert.NoError(t, req.ValidateRedirectURI())
}

func TestTokenRequest_ValidateUsername(t *testing.T) {
	req := &TokenRequest{}
	err := req.ValidateUsername()
	authErr := autherrors.ToAuthLibError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	req.Username = "alice"
	assert.NoError(t, req.ValidateUsername())
}

func TestTokenRequest_ValidatePassword(t *testing.T) {
	req := &TokenRequest{}
	err := req.ValidatePassword()
	authErr := autherrors.ToAuthLibError(err)
	assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)

	req.Password = "secret"
	assert.NoError(t, req.ValidatePassword())
}
