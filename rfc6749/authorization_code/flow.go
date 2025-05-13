package authorizationcode

import (
	"errors"
	"fmt"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/rfc6749"
	"github.com/tniah/authlib/types"
	"github.com/tniah/authlib/utils"
	"net/http"
	"time"
)

const EndpointToken = "token"

var (
	ErrNilAuthCode = errors.New("authorization code is nil")
	ErrNilToken    = errors.New("token is nil")
)

type Flow struct {
	*Config
	*rfc6749.TokenFlowMixin
}

func New(cfg *Config) *Flow {
	return &Flow{Config: cfg}
}

func Must(cfg *Config) (*Flow, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return New(cfg), nil
}

func (f *Flow) CheckGrantType(gt types.GrantType) bool {
	return gt.IsAuthorizationCode()
}

func (f *Flow) CheckResponseType(typ types.ResponseType) bool {
	return typ.IsCode()
}

func (f *Flow) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	if err := f.checkAuthEndpointHttpMethod(r); err != nil {
		return err
	}

	if err := f.checkClient(r); err != nil {
		return err
	}

	if err := f.validateRedirectURI(r); err != nil {
		return err
	}

	if err := f.validateResponseType(r); err != nil {
		return err
	}

	r.GrantType = types.GrantTypeAuthorizationCode
	for h, _ := range f.authReqValidators {
		if err := h.ValidateAuthorizationRequest(r); err != nil {
			return err
		}
	}

	return nil
}

func (f *Flow) ValidateConsentRequest(r *requests.AuthorizationRequest) error {
	if err := f.ValidateAuthorizationRequest(r); err != nil {
		return err
	}

	for h, _ := range f.consentReqValidators {
		if err := h.ValidateConsentRequest(r); err != nil {
			return err
		}
	}

	return nil
}

func (f *Flow) AuthorizationResponse(r *requests.AuthorizationRequest, rw http.ResponseWriter) error {
	if r.User == nil {
		return autherrors.AccessDeniedError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	authCode, err := f.genAuthCode(r)
	if err != nil {
		return err
	}

	params := map[string]interface{}{
		"code": authCode.GetCode(),
	}
	if r.State != "" {
		params["state"] = r.State
	}

	for h, _ := range f.authCodeProcessors {
		if err = h.ProcessAuthorizationCode(r, authCode, params); err != nil {
			return err
		}
	}

	if err = f.authCodeMgr.Save(r.Request.Context(), authCode); err != nil {
		return err
	}

	return utils.Redirect(rw, r.RedirectURI, params)
}

func (f *Flow) ValidateTokenRequest(r *requests.TokenRequest) error {
	if err := f.checkTokenEndpointHttpMethod(r); err != nil {
		return err
	}

	if err := f.validateGrantType(r); err != nil {
		return err
	}

	if err := f.authenticateClient(r); err != nil {
		return err
	}

	if err := f.validateAuthCode(r); err != nil {
		return err
	}

	for h, _ := range f.tokenReqValidators {
		if err := h.ValidateTokenRequest(r); err != nil {
			return err
		}
	}

	return nil
}

func (f *Flow) TokenResponse(r *requests.TokenRequest, rw http.ResponseWriter) error {
	if err := f.queryUserByAuthCode(r); err != nil {
		return err
	}

	token, err := f.genToken(r)
	if err != nil {
		return err
	}

	data := f.StandardTokenData(token)
	for h, _ := range f.tokenProcessors {
		if err = h.ProcessToken(r, token, data); err != nil {
			return err
		}
	}

	if err = f.tokenMgr.Save(r.Request.Context(), token); err != nil {
		return err
	}

	if err = f.authCodeMgr.DeleteByCode(r.Request.Context(), r.AuthCode.GetCode()); err != nil {
		return err
	}

	return f.HandleTokenResponse(rw, data)
}

func (f *Flow) checkAuthEndpointHttpMethod(r *requests.AuthorizationRequest) error {
	for _, method := range f.authEndpointHttpMethods {
		if r.Method() == method {
			return nil
		}
	}

	return autherrors.InvalidRequestError().WithDescription(fmt.Sprintf("unsupported http method \"%s\"", r.Method()))
}

func (f *Flow) checkTokenEndpointHttpMethod(r *requests.TokenRequest) error {
	for _, method := range f.tokenEndpointHttpMethods {
		if r.Method() == method {
			return nil
		}
	}

	return autherrors.InvalidRequestError().WithDescription(fmt.Sprintf("unsupported http method \"%s\"", r.Method()))
}

func (f *Flow) checkClient(r *requests.AuthorizationRequest) error {
	if err := r.ValidateClientID(true); err != nil {
		return err
	}

	client, err := f.clientMgr.QueryByClientID(r.Request.Context(), r.ClientID)
	if err != nil {
		return err
	}

	if client == nil {
		return autherrors.InvalidRequestError().
			WithDescription("No client was found that matches \"client_id\" value").
			WithState(r.State)
	}

	r.Client = client
	return nil
}

func (f *Flow) validateRedirectURI(r *requests.AuthorizationRequest) error {
	if r.RedirectURI == "" {
		r.RedirectURI = r.Client.GetDefaultRedirectURI()
		if r.RedirectURI == "" {
			return autherrors.InvalidRequestError().
				WithDescription("Missing \"redirect_uri\" in request").
				WithState(r.State)
		}

		return nil
	}

	if allowed := r.Client.CheckRedirectURI(r.RedirectURI); !allowed {
		return autherrors.InvalidRequestError().
			WithDescription("\"redirect_uri\" is not supported by client").
			WithState(r.State)
	}

	return nil
}

func (f *Flow) validateResponseType(r *requests.AuthorizationRequest) error {
	if err := r.ValidateResponseType(true); err != nil {
		return err
	}

	if valid := r.ResponseType.IsCode(); !valid {
		return autherrors.UnsupportedResponseTypeError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	if allowed := r.Client.CheckResponseType(r.ResponseType); !allowed {
		return autherrors.UnauthorizedClientError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (f *Flow) genAuthCode(r *requests.AuthorizationRequest) (models.AuthorizationCode, error) {
	authCode := f.authCodeMgr.New()
	if authCode == nil {
		return nil, ErrNilAuthCode
	}

	if err := f.authCodeMgr.Generate(authCode, r); err != nil {
		return nil, err
	}

	return authCode, nil
}

func (f *Flow) validateGrantType(r *requests.TokenRequest) error {
	if err := r.ValidateGrantType(); err != nil {
		return err
	}

	if valid := r.GrantType.IsAuthorizationCode(); !valid {
		return autherrors.UnsupportedGrantTypeError()
	}

	return nil
}

func (f *Flow) authenticateClient(r *requests.TokenRequest) error {
	cl, err := f.clientMgr.Authenticate(r.Request, f.supportedClientAuthMethods, EndpointToken)
	if err != nil || cl == nil {
		return autherrors.InvalidClientError()
	}

	r.Client = cl
	return nil
}

func (f *Flow) validateAuthCode(r *requests.TokenRequest) error {
	if err := r.ValidateCode(); err != nil {
		return err
	}

	authCode, err := f.authCodeMgr.QueryByCode(r.Request.Context(), r.Code)
	if err != nil {
		return err
	}

	if authCode == nil {
		return autherrors.InvalidGrantError().WithDescription("Invalid \"code\" in request")
	}

	if authCode.GetAuthTime().Add(authCode.GetExpiresIn()).Before(time.Now().UTC().Round(time.Second)) {
		return autherrors.InvalidGrantError().WithDescription("\"code\" has been expired")
	}

	redirectURI := authCode.GetRedirectURI()
	if redirectURI != "" && redirectURI != r.RedirectURI {
		return autherrors.InvalidGrantError().WithDescription("Invalid \"redirect_uri\" in request")
	}

	r.AuthCode = authCode
	return nil
}

func (f *Flow) queryUserByAuthCode(r *requests.TokenRequest) error {
	userID := r.AuthCode.GetUserID()
	if userID == "" {
		return autherrors.InvalidGrantError().WithDescription("No user could be found associated with this authorization code")
	}

	user, err := f.userMgr.QueryUserByCode(r.Request.Context(), r.AuthCode, r)
	if err != nil {
		return err
	}

	if user == nil {
		return autherrors.InvalidGrantError().WithDescription("No user could be found associated with this authorization code")
	}

	r.User = user
	return nil
}

func (f *Flow) genToken(r *requests.TokenRequest) (models.Token, error) {
	token := f.tokenMgr.New()
	if token == nil {
		return nil, ErrNilToken
	}

	r.Scopes = r.AuthCode.GetScopes()
	if err := f.tokenMgr.Generate(token, r, r.Client.CheckGrantType(types.GrantTypeRefreshToken)); err != nil {
		return nil, err
	}

	return token, nil
}
