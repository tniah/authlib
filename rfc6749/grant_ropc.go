package rfc6749

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/requests"
	"net/http"
)

type ROPCGrant struct {
	authenticateClient  AuthenticateClient
	authenticateUser    AuthenticateUser
	generateAccessToken GenerateAccessToken
	TokenGrantMixin
}

func NewROPCGrant(
	authenticateClient AuthenticateClient,
	authenticateUser AuthenticateUser,
	generateAccessToken GenerateAccessToken,
) *ROPCGrant {
	return &ROPCGrant{
		authenticateClient:  authenticateClient,
		authenticateUser:    authenticateUser,
		generateAccessToken: generateAccessToken,
	}
}

func (grant *ROPCGrant) CheckGrantType(grantType string) bool {
	return grantType == GrantTypeROPC
}

func (grant *ROPCGrant) ValidateTokenRequest(r *requests.TokenRequest) error {
	client, authMethod, err := grant.authenticateClient(r.Request)
	if err != nil {
		return autherrors.InvalidClientError()
	}

	if !client.CheckGrantType(GrantTypeROPC) {
		return autherrors.UnauthorizedClientError().WithDescription(ErrUnsupportedROPCGrant)
	}

	username := r.Username
	if username == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingUsername)
	}

	password := r.Password
	if password == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingPassword)
	}

	user, err := grant.authenticateUser(username, password)
	if err != nil {
		return autherrors.InvalidRequestError().WithDescription(ErrUsernameOrPasswordIncorrect)
	}

	r.Client = client
	r.TokenEndpointAuthMethod = authMethod
	r.User = user
	return nil
}

func (grant *ROPCGrant) TokenResponse(rw http.ResponseWriter, r *requests.TokenRequest) error {
	token, err := grant.generateAccessToken(GrantTypeROPC, r, r.Client.CheckGrantType(GrantTypeRefreshToken))
	if err != nil {
		return err
	}

	data := grant.StandardTokenData(token)
	// TODO implement a hook
	return grant.HandleTokenResponse(rw, data)
}
