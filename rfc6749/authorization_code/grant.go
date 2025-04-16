package authorizationcode

import (
	"errors"
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
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

func (g *Grant) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	if err := g.checkClient(r); err != nil {
		return err
	}

	if err := g.validateRedirectURI(r); err != nil {
		return err
	}

	if err := g.validateResponseType(r); err != nil {
		return err
	}

	r.GrantType = g.GrantType()
	return nil
}

func (g *Grant) AuthorizationResponse(r *requests.AuthorizationRequest, rw http.ResponseWriter) error {
	if r.User == nil {
		return autherrors.AccessDeniedError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	authCode, err := g.genAuthCode(r)
	if err != nil {
		return err
	}

	params := map[string]interface{}{
		ParamCode: authCode.GetCode(),
	}

	if r.State != "" {
		params[ParamState] = r.State
	}

	return common.Redirect(rw, r.RedirectURI, params)
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

func (g *Grant) checkClient(r *requests.AuthorizationRequest) error {
	if err := r.ValidateClientID(true); err != nil {
		return err
	}

	client, err := g.clientMgr.QueryByClientID(r.Request.Context(), r.ClientID)
	if err != nil {
		return err
	}

	if client == nil {
		return autherrors.InvalidRequestError().WithDescription(ErrClientNotFound).WithState(r.State)
	}

	r.Client = client
	return nil
}

func (g *Grant) validateRedirectURI(r *requests.AuthorizationRequest) error {
	if r.RedirectURI == "" {
		r.RedirectURI = r.Client.GetDefaultRedirectURI()

		if r.RedirectURI == "" {
			return autherrors.InvalidRequestError().WithDescription(ErrMissingRedirectURI).WithState(r.State)
		}

		return nil
	}

	if allowed := r.Client.CheckRedirectURI(r.RedirectURI); !allowed {
		return autherrors.InvalidRequestError().WithDescription(ErrUnsupportedRedirectURI).WithState(r.State)
	}

	return nil
}

func (g *Grant) validateResponseType(r *requests.AuthorizationRequest) error {
	if err := r.ValidateResponseType(ResponseTypeCode); err != nil {
		return err
	}

	if allowed := r.Client.CheckResponseType(string(r.ResponseType)); !allowed {
		return autherrors.UnauthorizedClientError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (g *Grant) genAuthCode(r *requests.AuthorizationRequest) (models.AuthorizationCode, error) {
	authCode := g.authCodeMgr.New()
	if authCode == nil {
		return nil, ErrNilAuthCode
	}

	if err := g.authCodeMgr.Generate(authCode, r); err != nil {
		return nil, err
	}

	if err := g.authCodeMgr.Save(r.Request.Context(), authCode); err != nil {
		return nil, err
	}

	return authCode, nil
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
