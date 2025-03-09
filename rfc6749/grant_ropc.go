package rfc6749

import (
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"net/http"
)

type (
	ROPCGrant struct {
		clientMgr        ClientManager
		tokenMgr         TokenManager
		authenticateUser AuthenticateUser
		TokenGrantMixin
	}

	AuthenticateUser func(username string, password string) (models.User, error)
)

func NewROPCGrant(clientMgr ClientManager, tokenMgr TokenManager, authenticateUser AuthenticateUser) *ROPCGrant {
	return &ROPCGrant{
		clientMgr:        clientMgr,
		tokenMgr:         tokenMgr,
		authenticateUser: authenticateUser,
	}
}

func (grant *ROPCGrant) CheckGrantType(grantType string) bool {
	return grantType == GrantTypeROPC
}

func (grant *ROPCGrant) ValidateTokenRequest(r *requests.TokenRequest) error {
	client, authMethod, err := grant.clientMgr.Authenticate(r.Request)
	if err != nil {
		return errors.NewInvalidClientError()
	}

	if !client.CheckGrantType(GrantTypeROPC) {
		return errors.NewUnauthorizedClientError(errors.WithDescription(ErrUnsupportedROPCGrant))
	}

	username := r.Username
	if username == "" {
		return errors.NewInvalidRequestError(errors.WithDescription(ErrMissingUsername))
	}

	password := r.Password
	if password == "" {
		return errors.NewInvalidRequestError(errors.WithDescription(ErrMissingPassword))
	}

	user, err := grant.authenticateUser(username, password)
	if err != nil {
		return errors.NewInvalidRequestError(errors.WithDescription(ErrUsernameOrPasswordIncorrect))
	}

	r.Client = client
	r.TokenEndpointAuthMethod = authMethod
	r.User = user
	return nil
}

func (grant *ROPCGrant) TokenResponse(rw http.ResponseWriter, r *requests.TokenRequest) error {
	token, err := grant.tokenMgr.GenerateAccessToken(GrantTypeROPC, r, r.Client.CheckGrantType(GrantTypeRefreshToken))
	if err != nil {
		return err
	}

	return grant.HandleTokenResponse(rw, token.GetData())
}
