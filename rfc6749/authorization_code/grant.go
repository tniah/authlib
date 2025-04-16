package authorizationcode

import (
	"errors"
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/rfc6749"
	"net/http"
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

func (g *Grant) ValidateTokenRequest(r *requests.TokenRequest) error {
	if err := g.checkTokenRequestParams(r); err != nil {
		return err
	}

	if err := g.authenticateClient(r); err != nil {
		return err
	}

	if err := g.validateAuthCode(r); err != nil {
		return err
	}

	return nil
}

func (g *Grant) TokenResponse(r *requests.TokenRequest, rw http.ResponseWriter) error {
	if err := g.queryUserByAuthCode(r); err != nil {
		return err
	}

	token, err := g.genToken(r)
	if err != nil {
		return err
	}

	if err = g.authCodeMgr.DeleteByCode(r.Request.Context(), r.AuthCode.GetCode()); err != nil {
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

func (g *Grant) checkTokenRequestParams(r *requests.TokenRequest) error {
	if err := g.CheckTokenRequest(r.Request); err != nil {
		return err
	}

	if err := r.ValidateGrantType(g.GrantType()); err != nil {
		return err
	}

	if err := r.ValidateCode(); err != nil {
		return err
	}

	return nil
}

func (g *Grant) authenticateClient(r *requests.TokenRequest) error {
	client, err := g.clientMgr.Authenticate(r.Request, g.supportedClientAuthMethods, EndpointToken)
	if err != nil {
		return err
	}

	if client == nil {
		return autherrors.InvalidClientError()
	}

	r.Client = client
	return nil
}

func (g *Grant) validateAuthCode(r *requests.TokenRequest) error {
	authCode, err := g.authCodeMgr.QueryByCode(r.Request.Context(), r.Code)
	if err != nil {
		return err
	}

	if authCode == nil {
		return autherrors.InvalidGrantError().WithDescription(ErrInvalidAuthCode)
	}

	if authCode.GetAuthTime().Add(authCode.GetExpiresIn()).Before(time.Now()) {
		return autherrors.InvalidGrantError().WithDescription(ErrInvalidAuthCode)
	}

	redirectURI := authCode.GetRedirectURI()
	if redirectURI != "" && redirectURI != r.RedirectURI {
		return autherrors.InvalidGrantError().WithDescription(ErrInvalidRedirectURI)
	}

	r.AuthCode = authCode
	return nil
}

func (g *Grant) queryUserByAuthCode(r *requests.TokenRequest) error {
	userID := r.AuthCode.GetUserID()
	if userID == "" {
		return autherrors.InvalidGrantError().WithDescription(ErrUserNotFound)
	}

	user, err := g.userMgr.QueryByUserID(r.Request.Context(), userID)
	if err != nil {
		return err
	}

	if user == nil {
		return autherrors.InvalidGrantError().WithDescription(ErrUserNotFound)
	}

	r.User = user
	return nil
}

func (g *Grant) genToken(r *requests.TokenRequest) (models.Token, error) {
	token := g.tokenMgr.New()
	if token == nil {
		return nil, ErrNilToken
	}

	if err := g.tokenMgr.Generate(token, r); err != nil {
		return nil, err
	}

	if err := g.tokenMgr.Save(r.Request.Context(), token); err != nil {
		return nil, err
	}

	return token, nil
}
