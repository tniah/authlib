package rfc6749

import (
	"errors"
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/requests"
	"net/http"
	"time"
)

var (
	ErrMissingQueryClient         = errors.New("missing \"queryClient\"")
	ErrMissingAuthenticateClient  = errors.New("missing \"authenticateClient\"")
	ErrMissingQueryUser           = errors.New("missing \"queryUser\"")
	ErrMissingQueryAuthCode       = errors.New("missing \"queryAuthCode\"")
	ErrMissingGenerateAuthCode    = errors.New("missing \"generateAuthCode\"")
	ErrMissingDeleteAuthCode      = errors.New("missing \"deleteAuthCode\"")
	ErrMissingGenerateAccessToken = errors.New("missing \"generateAccessToken\"")
)

type AuthorizationCodeGrant struct {
	queryClient         QueryClient
	authenticateClient  AuthenticateClient
	queryUser           QueryUser
	queryAuthCode       QueryAuthCode
	generateAuthCode    GenerateAuthCode
	deleteAuthCode      DeleteAuthCode
	generateAccessToken GenerateAccessToken
	AuthorizationGrantMixin
	TokenGrantMixin
}

func NewAuthorizationCodeGrant(
	queryClient QueryClient,
	authenticateClient AuthenticateClient,
	queryUser QueryUser,
	queryAuthCode QueryAuthCode,
	generateAuthCode GenerateAuthCode,
	deleteAuthCode DeleteAuthCode,
	generateAccessToken GenerateAccessToken,
) *AuthorizationCodeGrant {
	return &AuthorizationCodeGrant{
		queryClient:         queryClient,
		authenticateClient:  authenticateClient,
		queryUser:           queryUser,
		queryAuthCode:       queryAuthCode,
		generateAuthCode:    generateAuthCode,
		deleteAuthCode:      deleteAuthCode,
		generateAccessToken: generateAccessToken,
	}
}

func MustAuthorizationCodeGrant(
	queryClient QueryClient,
	authenticateClient AuthenticateClient,
	queryUser QueryUser,
	queryAuthCode QueryAuthCode,
	generateAuthCode GenerateAuthCode,
	deleteAuthCode DeleteAuthCode,
	generateAccessToken GenerateAccessToken,
) (*AuthorizationCodeGrant, error) {
	g := &AuthorizationCodeGrant{}

	if err := g.MustQueryClient(queryClient); err != nil {
		return nil, err
	}

	if err := g.MustAuthenticateClient(authenticateClient); err != nil {
		return nil, err
	}

	if err := g.MustQueryUser(queryUser); err != nil {
		return nil, err
	}

	if err := g.MustQueryAuthCode(queryAuthCode); err != nil {
		return nil, err
	}

	if err := g.MustGenerateAuthCode(generateAuthCode); err != nil {
		return nil, err
	}

	if err := g.MustDeleteAuthCode(deleteAuthCode); err != nil {
		return nil, err
	}

	if err := g.MustGenerateAccessToken(generateAccessToken); err != nil {
		return nil, err
	}

	return g, nil
}

func (grant *AuthorizationCodeGrant) SetQueryClient(fn QueryClient) {
	grant.queryClient = fn
}

func (grant *AuthorizationCodeGrant) MustQueryClient(fn QueryClient) error {
	if fn == nil {
		return ErrMissingQueryClient
	}

	grant.SetQueryClient(fn)
	return nil
}

func (grant *AuthorizationCodeGrant) SetAuthenticateClient(fn AuthenticateClient) {
	grant.authenticateClient = fn
}

func (grant *AuthorizationCodeGrant) MustAuthenticateClient(fn AuthenticateClient) error {
	if fn == nil {
		return ErrMissingAuthenticateClient
	}

	grant.SetAuthenticateClient(fn)
	return nil
}

func (grant *AuthorizationCodeGrant) SetQueryUser(fn QueryUser) {
	grant.queryUser = fn
}

func (grant *AuthorizationCodeGrant) MustQueryUser(fn QueryUser) error {
	if fn == nil {
		return ErrMissingQueryUser
	}

	grant.SetQueryUser(fn)
	return nil
}

func (grant *AuthorizationCodeGrant) SetQueryAuthCode(fn QueryAuthCode) {
	grant.queryAuthCode = fn
}

func (grant *AuthorizationCodeGrant) MustQueryAuthCode(fn QueryAuthCode) error {
	if fn == nil {
		return ErrMissingQueryAuthCode
	}

	grant.SetQueryAuthCode(fn)
	return nil
}

func (grant *AuthorizationCodeGrant) SetGenerateAuthCode(fn GenerateAuthCode) {
	grant.generateAuthCode = fn
}

func (grant *AuthorizationCodeGrant) MustGenerateAuthCode(fn GenerateAuthCode) error {
	if fn == nil {
		return ErrMissingGenerateAuthCode
	}

	grant.SetGenerateAuthCode(fn)
	return nil
}

func (grant *AuthorizationCodeGrant) SetDeleteAuthCode(fn DeleteAuthCode) {
	grant.deleteAuthCode = fn
}

func (grant *AuthorizationCodeGrant) MustDeleteAuthCode(fn DeleteAuthCode) error {
	if fn == nil {
		return ErrMissingDeleteAuthCode
	}

	grant.SetDeleteAuthCode(fn)
	return nil
}

func (grant *AuthorizationCodeGrant) SetGenerateAccessToken(fn GenerateAccessToken) {
	grant.generateAccessToken = fn
}

func (grant *AuthorizationCodeGrant) MustGenerateAccessToken(fn GenerateAccessToken) error {
	if fn == nil {
		return ErrMissingGenerateAccessToken
	}

	grant.SetGenerateAccessToken(fn)
	return nil
}

func (grant *AuthorizationCodeGrant) CheckResponseType(responseType string) bool {
	return responseType == ResponseTypeCode
}

func (grant *AuthorizationCodeGrant) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	clientID := r.ClientID
	state := r.State

	if clientID == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingClientID).WithState(state)
	}

	client, err := grant.queryClient(r.Request.Context(), clientID)
	if err != nil {
		return err
	}
	if client == nil {
		return autherrors.InvalidRequestError().WithDescription(ErrClientIDNotFound).WithState(state)
	}

	redirectURI, err := grant.ValidateRedirectURI(r, client)
	if err != nil {
		return err
	}

	responseType := r.ResponseType
	if !grant.CheckResponseType(responseType) {
		return autherrors.UnsupportedResponseTypeError().WithState(state).WithRedirectURI(redirectURI)
	}
	if allowed := client.CheckResponseType(responseType); !allowed {
		return autherrors.UnauthorizedClientError().WithState(state).WithRedirectURI(redirectURI)
	}

	r.Client = client
	r.RedirectURI = redirectURI

	// TODO - Validate requested scopes
	return nil
}

func (grant *AuthorizationCodeGrant) AuthorizationResponse(rw http.ResponseWriter, r *requests.AuthorizationRequest) error {
	if r.UserID == "" {
		return autherrors.AccessDeniedError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	authCode, err := grant.generateAuthCode(GrantTypeAuthorizationCode, r)
	if err != nil {
		return err
	}
	if authCode == nil {
		return autherrors.AccessDeniedError()
	}

	params := map[string]interface{}{ParamCode: authCode.GetCode()}
	if r.State != "" {
		params[ParamState] = r.State
	}

	return common.Redirect(rw, r.RedirectURI, params)
}

func (grant *AuthorizationCodeGrant) CheckGrantType(grantType string) bool {
	return grantType == GrantTypeAuthorizationCode
}

func (grant *AuthorizationCodeGrant) ValidateTokenRequest(r *requests.TokenRequest) error {
	client, authMethod, err := grant.authenticateClient(r.Request)
	if err != nil {
		return autherrors.InvalidClientError()
	}

	if !client.CheckGrantType(GrantTypeAuthorizationCode) {
		return autherrors.UnauthorizedClientError().WithDescription(ErrUnsupportedGrantType)
	}

	code := r.Code
	if code == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingCode)
	}

	authCode, err := grant.queryAuthCode(r.Request.Context(), code)
	if err != nil {
		return autherrors.InvalidGrantError().WithDescription(ErrInvalidCode)
	}

	if authCode.GetAuthTime().Add(authCode.GetExpiresIn()).Before(time.Now()) {
		return autherrors.InvalidGrantError().WithDescription(ErrInvalidCode)
	}

	redirectURI := authCode.GetRedirectURI()
	if redirectURI != "" && redirectURI != r.RedirectURI {
		return autherrors.InvalidGrantError().WithDescription(ErrInvalidRedirectURI)
	}

	userID := authCode.GetUserID()
	if userID == "" {
		return autherrors.InvalidGrantError().WithDescription(ErrUserNotFound)
	}

	user, err := grant.queryUser(r.Request.Context(), userID)
	if err != nil {
		return autherrors.InvalidGrantError().WithDescription(ErrUserNotFound)
	}

	r.Client = client
	r.TokenEndpointAuthMethod = authMethod
	r.AuthorizationCode = authCode
	r.User = user
	return nil
}

func (grant *AuthorizationCodeGrant) TokenResponse(rw http.ResponseWriter, r *requests.TokenRequest) error {
	token, err := grant.generateAccessToken(GrantTypeAuthorizationCode, r, r.Client.CheckGrantType(GrantTypeRefreshToken))
	if err != nil {
		return err
	}

	if err = grant.deleteAuthCode(r.Request.Context(), r.AuthorizationCode.GetCode()); err != nil {
		return err
	}

	data := grant.StandardTokenData(token)
	// TODO implement a hook
	return grant.HandleTokenResponse(rw, data)
}
