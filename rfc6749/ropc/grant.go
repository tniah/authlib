package ropc

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/rfc6749"
	"net/http"
	"strings"
)

var defaultClientAuthMethods = map[string]bool{
	AuthMethodClientSecretBasic: true,
}

type Grant struct {
	clientMgr                  ClientManager
	userMgr                    UserManager
	tokenManager               TokenManager
	supportedClientAuthMethods map[string]bool
	*rfc6749.TokenGrantMixin
}

func New() *Grant {
	g := &Grant{
		TokenGrantMixin: &rfc6749.TokenGrantMixin{},
	}
	g.SetGrantType(GrantTypeROPC)
	g.SetClientAuthMethods(defaultClientAuthMethods)
	return g
}

func Must(clientMgr ClientManager, userMgr UserManager, tokenMgr TokenManager) (*Grant, error) {
	g := New()
	if err := g.MustClientManager(clientMgr); err != nil {
		return nil, err
	}

	if err := g.MustUserManager(userMgr); err != nil {
		return nil, err
	}

	if err := g.MustTokenManager(tokenMgr); err != nil {
		return nil, err
	}

	return g, nil
}

func (g *Grant) SetClientManager(mgr ClientManager) {
	g.clientMgr = mgr
}

func (g *Grant) MustClientManager(mgr ClientManager) error {
	if mgr == nil {
		return ErrNilClientManager
	}

	g.SetClientManager(mgr)
	return nil
}

func (g *Grant) SetUserManager(mgr UserManager) {
	g.userMgr = mgr
}

func (g *Grant) MustUserManager(userMgr UserManager) error {
	if userMgr == nil {
		return ErrNilUserManager
	}

	g.SetUserManager(userMgr)
	return nil
}

func (g *Grant) SetTokenManager(mgr TokenManager) {
	g.tokenManager = mgr
}

func (g *Grant) MustTokenManager(mgr TokenManager) error {
	if mgr == nil {
		return ErrNilTokenManager
	}

	g.SetTokenManager(mgr)
	return nil
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
