package ropc

import (
	"errors"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/rfc6749"
	"net/http"
	"strings"
)

var ErrNilToken = errors.New("token is nil")

type Grant struct {
	*Config
	*rfc6749.TokenGrantMixin
}

func New(cfg *Config) *Grant {
	return &Grant{Config: cfg}
}

func Must(cfg *Config) (*Grant, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return New(cfg), nil
}

func (g *Grant) GrantType() string {
	return GrantTypeROPC
}

func (g *Grant) CheckGrantType(gt string) bool {
	if gt == "" {
		return false
	}
	return gt == g.GrantType()
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
	token := g.tokenMgr.New()
	if token == nil {
		return ErrNilToken
	}

	if err = g.tokenMgr.Generate(GrantTypeROPC, token, client, user, scopes, includeRefreshToken); err != nil {
		return err
	}

	if err = g.tokenMgr.Save(r.Context(), token); err != nil {
		return err
	}

	data := g.StandardTokenData(token)
	return g.HandleTokenResponse(rw, data)
}

func (g *Grant) checkParams(r *http.Request) error {
	if err := g.CheckTokenRequest(r); err != nil {
		return err
	}

	grantType := r.PostFormValue(ParamGrantType)
	if grantType == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingGrantType)
	}

	if !g.CheckGrantType(grantType) {
		return autherrors.UnsupportedGrantTypeError()
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
