package authorizationcode

import (
	"errors"
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/rfc6749"
	"net/http"
	"strings"
	"time"
)

var (
	ErrNilAuthCode = errors.New("authorization code is nil")
	ErrNilToken    = errors.New("token is nil")
)

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
	return GrantTypeAuthorizationCode
}

func (g *Grant) CheckGrantType(gt string) bool {
	if gt == "" {
		return false
	}
	return gt == g.GrantType()
}

func (g *Grant) ResponseType() string {
	return ResponseTypeCode
}

func (g *Grant) CheckResponseType(typ string) bool {
	if typ == "" {
		return false
	}
	return typ == g.ResponseType()
}

func (g *Grant) AuthorizationResponse(r *http.Request, rw http.ResponseWriter) error {
	state := r.URL.Query().Get(ParamState)
	client, err := g.checkClient(r, state)
	if err != nil {
		return err
	}

	redirectURI, err := g.ValidateRedirectURI(r, client, state)
	if err != nil {
		return err
	}

	if err = g.validateResponseType(r, client, redirectURI, state); err != nil {
		return err
	}

	user, err := g.authenticateUser(r, client, redirectURI, state)
	if err != nil {
		return err
	}

	authCode := g.authCodeMgr.New()
	if authCode == nil {
		return ErrNilAuthCode
	}

	scopes := strings.Fields(r.URL.Query().Get(ParamScope))
	if err = g.authCodeMgr.Generate(
		GrantTypeAuthorizationCode,
		ResponseTypeCode,
		authCode, client, user, scopes, redirectURI, state, r,
	); err != nil {
		return err
	}

	if err = g.authCodeMgr.Save(r.Context(), authCode); err != nil {
		return err
	}

	params := map[string]interface{}{
		ParamCode: authCode.GetCode(),
	}
	if state != "" {
		params[ParamState] = state
	}

	return common.Redirect(rw, redirectURI, params)
}

func (g *Grant) TokenResponse(r *http.Request, rw http.ResponseWriter) error {
	if err := g.checkTokenRequestParams(r); err != nil {
		return err
	}

	client, err := g.authenticateClient(r)
	if err != nil {
		return err
	}

	authCode, err := g.validateAuthCode(r)
	if err != nil {
		return err
	}

	user, err := g.queryUserByAuthCode(r, authCode)
	if err != nil {
		return err
	}

	scopes := strings.Fields(r.FormValue(ParamScope))
	includeRefreshToken := client.CheckGrantType(GrantTypeRefreshToken)
	token := g.tokenMgr.New()
	if token == nil {
		return ErrNilToken
	}

	if err = g.tokenMgr.Generate(GrantTypeAuthorizationCode, token, client, user, scopes, includeRefreshToken); err != nil {
		return err
	}

	if err = g.tokenMgr.Save(r.Context(), token); err != nil {
		return err
	}

	if err = g.authCodeMgr.DeleteByCode(r.Context(), authCode.GetCode()); err != nil {
		return err
	}

	data := g.StandardTokenData(token)
	return g.HandleTokenResponse(rw, data)
}

func (g *Grant) checkClient(r *http.Request, state string) (client models.Client, err error) {
	clientID := r.URL.Query().Get(ParamClientID)
	if clientID == "" {
		return nil, autherrors.InvalidRequestError().WithDescription(ErrMissingClientID).WithState(state)
	}

	if client, err = g.clientMgr.QueryByClientID(r.Context(), clientID); err != nil {
		return nil, err
	}

	if client == nil {
		return nil, autherrors.InvalidRequestError().WithDescription(ErrClientNotFound).WithState(state)
	}

	return client, nil
}

func (g *Grant) ValidateRedirectURI(r *http.Request, client models.Client, state string) (string, error) {
	redirectURI := r.URL.Query().Get(ParamRedirectURI)
	if redirectURI == "" {
		redirectURI = client.GetDefaultRedirectURI()

		if redirectURI == "" {
			return "", autherrors.InvalidRequestError().WithDescription(ErrMissingRedirectURI).WithState(state)
		}

		return redirectURI, nil
	}

	if allowed := client.CheckRedirectURI(redirectURI); !allowed {
		return "", autherrors.InvalidRequestError().WithDescription(ErrUnsupportedRedirectURI).WithState(state)
	}

	return redirectURI, nil
}

func (g *Grant) validateResponseType(r *http.Request, client models.Client, redirectURI, state string) error {
	responseType := r.URL.Query().Get(ParamResponseType)

	if responseType == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingResponseType).WithRedirectURI(redirectURI).WithState(state)
	}

	if responseType != g.ResponseType() {
		return autherrors.UnsupportedResponseTypeError().WithRedirectURI(redirectURI).WithState(state)
	}

	if allowed := client.CheckResponseType(responseType); !allowed {
		return autherrors.UnauthorizedClientError().WithRedirectURI(redirectURI).WithState(state)
	}

	return nil
}

func (g *Grant) authenticateUser(r *http.Request, client models.Client, redirectURI, state string) (models.User, error) {
	user, err := g.userMgr.Authenticate(r, client)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, autherrors.AccessDeniedError().WithState(state).WithRedirectURI(redirectURI)
	}

	return user, nil
}

func (g *Grant) checkTokenRequestParams(r *http.Request) error {
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

	code := r.PostFormValue(ParamCode)
	if code == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingAuthCode)
	}

	return nil
}

func (g *Grant) authenticateClient(r *http.Request) (models.Client, error) {
	client, err := g.clientMgr.Authenticate(r, g.supportedClientAuthMethods, EndpointToken)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, autherrors.InvalidClientError()
	}

	return client, nil
}

func (g *Grant) validateAuthCode(r *http.Request) (models.AuthorizationCode, error) {
	authCode, err := g.authCodeMgr.QueryByCode(r.Context(), r.PostFormValue(ParamCode))
	if err != nil {
		return nil, err
	}

	if authCode == nil {
		return nil, autherrors.InvalidGrantError().WithDescription(ErrInvalidAuthCode)
	}

	if authCode.GetAuthTime().Add(authCode.GetExpiresIn()).Before(time.Now()) {
		return nil, autherrors.InvalidGrantError().WithDescription(ErrInvalidAuthCode)
	}

	redirectURI := authCode.GetRedirectURI()
	if redirectURI != "" && redirectURI != r.PostFormValue(ParamRedirectURI) {
		return nil, autherrors.InvalidGrantError().WithDescription(ErrInvalidRedirectURI)
	}

	return authCode, nil
}

func (g *Grant) queryUserByAuthCode(r *http.Request, authCode models.AuthorizationCode) (models.User, error) {
	userID := authCode.GetUserID()
	if userID == "" {
		return nil, autherrors.InvalidGrantError().WithDescription(ErrUserNotFound)
	}

	user, err := g.userMgr.QueryByUserID(r.Context(), userID)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, autherrors.InvalidGrantError().WithDescription(ErrUserNotFound)
	}

	return user, nil
}
