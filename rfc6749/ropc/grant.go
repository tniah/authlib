package ropc

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/rfc6749"
	"net/http"
	"strings"
)

type Grant struct {
	clientMgr                  ClientManager
	userMgr                    UserManager
	tokenManager               TokenManager
	supportedClientAuthMethods map[string]bool
	*rfc6749.TokenGrantMixin
}

func New(clientMgr ClientManager, userMgr UserManager, tokenMgr TokenManager) (*Grant, error) {
	if clientMgr == nil {
		return nil, ErrNilClientManager
	}

	if userMgr == nil {
		return nil, ErrNilUserManager
	}

	if tokenMgr == nil {
		return nil, ErrNilTokenManager
	}

	return &Grant{
		clientMgr:    clientMgr,
		userMgr:      userMgr,
		tokenManager: tokenMgr,
		supportedClientAuthMethods: map[string]bool{
			AuthMethodClientSecretBasic: true,
		},
		TokenGrantMixin: &rfc6749.TokenGrantMixin{
			GrantType: GrantTypeROPC,
		},
	}, nil
}

func (g *Grant) WithClientAuthMethods(methods map[string]bool) *Grant {
	g.supportedClientAuthMethods = methods
	return g
}

func (g *Grant) TokenResponse(r *http.Request, rw http.ResponseWriter) error {
	if err := g.checkParams(r); err != nil {
		return err
	}

	client, err := g.authenticateClient(r)
	if err != nil {
		return err
	}

	user, err := g.authenticateUser(r, client)
	if err != nil {
		return err
	}

	scopes := strings.Fields(r.FormValue(ParamScope))
	includeRefreshToken := client.CheckGrantType(GrantTypeRefreshToken)
	token, err := g.tokenManager.GenerateAccessToken(r, GrantTypeROPC, client, user, scopes, includeRefreshToken)
	if err != nil {
		return err
	}

	data := g.StandardTokenData(token)
	return g.HandleTokenResponse(rw, data)
}

func (g *Grant) checkParams(r *http.Request) error {
	if err := g.CheckTokenRequest(r); err != nil {
		return err
	}

	username := r.PostFormValue(ParamUsername)
	if username == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingUsername)
	}

	password := r.PostFormValue(ParamPassword)
	if password == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingPassword)
	}

	return nil
}

func (g *Grant) authenticateClient(r *http.Request) (client models.Client, err error) {
	if client, err = g.clientMgr.Authenticate(r, g.supportedClientAuthMethods, EndpointToken); err != nil {
		return nil, err
	}

	if client == nil {
		return nil, autherrors.InvalidClientError()
	}

	if !client.CheckGrantType(GrantTypeROPC) {
		return nil, autherrors.UnauthorizedClientError().WithDescription(ErrClientUnsupportedROPC)
	}

	return client, nil
}

func (g *Grant) authenticateUser(r *http.Request, client models.Client) (user models.User, err error) {
	username := r.PostFormValue(ParamUsername)
	password := r.PostFormValue(ParamPassword)

	if user, err = g.userMgr.Authenticate(username, password, client, r); err != nil {
		return nil, err
	}

	if user == nil {
		return nil, autherrors.InvalidRequestError().WithDescription(ErrIncorrectUsernameOrPassword)
	}

	return user, nil
}
