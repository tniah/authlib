package rfc6749

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/requests"
	"net/http"
	"time"
)

type AuthorizationCodeGrant struct {
	userMgr     UserManager
	clientMgr   ClientManager
	authCodeMgr AuthorizationCodeManager
	tokenMgr    TokenManager
	AuthorizationGrantMixin
	TokenGrantMixin
}

func NewAuthorizationCodeGrant(
	userMgr UserManager,
	clientMgr ClientManager,
	authCodeMgr AuthorizationCodeManager,
	tokenMgr TokenManager,
) *AuthorizationCodeGrant {
	return &AuthorizationCodeGrant{
		userMgr:     userMgr,
		clientMgr:   clientMgr,
		authCodeMgr: authCodeMgr,
		tokenMgr:    tokenMgr,
	}
}

func (grant *AuthorizationCodeGrant) CheckResponseType(responseType constants.ResponseType) bool {
	return responseType == constants.ResponseTypeCode
}

func (grant *AuthorizationCodeGrant) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	clientID := r.ClientID
	state := r.State

	if clientID == "" {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrMissingClientID),
			errors.WithState(state))
	}

	client, err := grant.clientMgr.QueryByClientID(r.Request.Context(), clientID)
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

	authCode, err := grant.authCodeMgr.Generate(constants.GrantTypeAuthorizationCode, r)
	if err != nil {
		return err
	}

	if err = grant.authCodeMgr.Save(r.Request.Context(), authCode); err != nil {
		return err
	}

	params := map[string]interface{}{
		constants.ParamCode: authCode.GetCode(),
	}
	if r.State != "" {
		params[constants.ParamState] = r.State
	}

	return common.Redirect(rw, r.RedirectURI, params)
}

func (grant *AuthorizationCodeGrant) CheckGrantType(grantType constants.GrantType) bool {
	return grantType == constants.GrantTypeAuthorizationCode
}

func (grant *AuthorizationCodeGrant) ValidateTokenRequest(r *requests.TokenRequest) error {
	client, authMethod, err := grant.clientMgr.Authenticate(r.Request)
	if err != nil {
		return errors.NewInvalidClientError()
	}

	if !client.CheckGrantType(constants.GrantTypeAuthorizationCode) {
		return errors.NewUnauthorizedClientError(errors.WithDescription(ErrUnsupportedGrantType))
	}

	code := r.Code
	if code == "" {
		return errors.NewInvalidRequestError(errors.WithDescription(ErrMissingCode))
	}

	authCode, err := grant.authCodeMgr.QueryByCode(r.Request.Context(), code)
	if err != nil {
		return err
	}
	if authCode == nil {
		return errors.NewInvalidGrantError(errors.WithDescription(ErrInvalidCode))
	}

	redirectURI := authCode.GetRedirectURI()
	if redirectURI != "" && redirectURI != r.RedirectURI {
		return errors.NewInvalidGrantError(errors.WithDescription(ErrInvalidRedirectURI))
	}

	r.Client = client
	r.TokenEndpointAuthMethod = authMethod
	r.AuthorizationCode = authCode
	return nil
}

func (grant *AuthorizationCodeGrant) TokenResponse(rw http.ResponseWriter, r *requests.TokenRequest) error {
	userID := r.AuthorizationCode.GetUserID()
	if userID == "" {
		return errors.NewInvalidGrantError(errors.WithDescription(ErrUserNotFound))
	}

	user, err := grant.userMgr.GetByID(r.Request.Context(), userID)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.NewInvalidGrantError(errors.WithDescription(ErrUserNotFound))
	}

	token, err := grant.tokenMgr.GenerateAccessToken(constants.GrantTypeAuthorizationCode, user, r.Client, r.Scopes)
	if err != nil {
		return err
	}

	if err = grant.tokenMgr.SaveAccessToken(r.Request.Context(), token); err != nil {
		return err
	}

	if err = grant.authCodeMgr.DeleteByCode(r.Request.Context(), r.AuthorizationCode); err != nil {
		return err
	}

	// TODO implement a hook
	data := map[string]interface{}{
		ParamAccessToken: token.GetAccessToken(),
		ParamTokenType:   token.GetTokenType(),
		ParamExpiresIn:   int64(token.GetExpiresIn() / time.Second),
		ParamScopes:      token.GetScopes(),
	}
	return grant.HandleTokenResponse(rw, data)
}
