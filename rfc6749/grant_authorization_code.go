package rfc6749

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/requests"
	"net/http"
	"time"
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

func (grant *AuthorizationCodeGrant) CheckResponseType(responseType string) bool {
	return responseType == ResponseTypeCode
}

func (grant *AuthorizationCodeGrant) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	clientID := r.ClientID
	state := r.State

	if clientID == "" {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrMissingClientID),
			errors.WithState(state))
	}

	client, err := grant.queryClient(r.Request.Context(), clientID)
	if err != nil {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrClientIDNotFound),
			errors.WithState(state))
	}

	redirectURI, err := grant.ValidateRedirectURI(r, client)
	if err != nil {
		return err
	}

	responseType := r.ResponseType
	if !grant.CheckResponseType(responseType) {
		return errors.NewUnsupportedResponseTypeError(
			errors.WithState(state),
			errors.WithRedirectURI(redirectURI))
	}
	if allowed := client.CheckResponseType(responseType); !allowed {
		return errors.NewUnauthorizedClientError(
			errors.WithState(state),
			errors.WithRedirectURI(redirectURI))
	}

	r.Client = client
	r.RedirectURI = redirectURI

	// TODO - Validate requested scopes
	return nil
}

func (grant *AuthorizationCodeGrant) AuthorizationResponse(rw http.ResponseWriter, r *requests.AuthorizationRequest) error {
	if r.UserID == "" {
		return errors.NewAccessDeniedError(
			errors.WithState(r.State),
			errors.WithRedirectURI(r.RedirectURI))
	}

	authCode, err := grant.generateAuthCode(GrantTypeAuthorizationCode, r)
	if err != nil {
		return err
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
		return errors.NewInvalidClientError()
	}

	if !client.CheckGrantType(GrantTypeAuthorizationCode) {
		return errors.NewUnauthorizedClientError(errors.WithDescription(ErrUnsupportedGrantType))
	}

	code := r.Code
	if code == "" {
		return errors.NewInvalidRequestError(errors.WithDescription(ErrMissingCode))
	}

	authCode, err := grant.queryAuthCode(r.Request.Context(), code)
	if err != nil {
		return errors.NewInvalidGrantError(errors.WithDescription(ErrInvalidCode))
	}

	if authCode.GetAuthTime().Add(authCode.GetExpiresIn()).Before(time.Now()) {
		return errors.NewInvalidGrantError(errors.WithDescription(ErrInvalidCode))
	}

	redirectURI := authCode.GetRedirectURI()
	if redirectURI != "" && redirectURI != r.RedirectURI {
		return errors.NewInvalidGrantError(errors.WithDescription(ErrInvalidRedirectURI))
	}

	userID := authCode.GetUserID()
	if userID == "" {
		return errors.NewInvalidGrantError(errors.WithDescription(ErrUserNotFound))
	}

	user, err := grant.queryUser(r.Request.Context(), userID)
	if err != nil {
		return errors.NewInvalidGrantError(errors.WithDescription(ErrUserNotFound))
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

	// TODO implement a hook
	return grant.HandleTokenResponse(rw, token.GetData())
}
