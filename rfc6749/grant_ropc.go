package rfc6749

import (
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/requests"
	"net/http"
)

type ROPCGrant struct {
	clientAuthHandler    ClientAuthenticationHandler
	userAuthHandler      UserAuthenticationHandler
	accessTokenGenerator AccessTokenGenerator
	TokenGrantMixin
}

func NewROPCGrant(
	clientAuthHandler ClientAuthenticationHandler,
	userAuthHandler UserAuthenticationHandler,
	accessTokenGenerator AccessTokenGenerator,
) *ROPCGrant {
	return &ROPCGrant{
		clientAuthHandler:    clientAuthHandler,
		userAuthHandler:      userAuthHandler,
		accessTokenGenerator: accessTokenGenerator,
	}
}

func (grant *ROPCGrant) CheckGrantType(grantType string) bool {
	return grantType == GrantTypeROPC
}

func (grant *ROPCGrant) ValidateTokenRequest(r *requests.TokenRequest) error {
	client, authMethod, err := grant.clientAuthHandler(r.Request)
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

	user, err := grant.userAuthHandler(username, password)
	if err != nil {
		return errors.NewInvalidRequestError(errors.WithDescription(ErrUsernameOrPasswordIncorrect))
	}

	r.Client = client
	r.TokenEndpointAuthMethod = authMethod
	r.User = user
	return nil
}

func (grant *ROPCGrant) TokenResponse(rw http.ResponseWriter, r *requests.TokenRequest) error {
	token, err := grant.accessTokenGenerator(GrantTypeROPC, r, r.Client.CheckGrantType(GrantTypeRefreshToken))
	if err != nil {
		return err
	}

	return grant.HandleTokenResponse(rw, token.GetData())
}
