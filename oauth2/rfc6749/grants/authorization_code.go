package grants

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/oauth2/rfc6749/errors"
	"github.com/tniah/authlib/oauth2/rfc6749/manage"
	"net/http"
)

type AuthorizationCodeGrant struct {
	clientManager   *manage.ClientManager
	authCodeManager *manage.AuthorizationCodeManager
	*AuthorizationGrantMixin
}

func NewAuthorizationCodeGrant(clientManager *manage.ClientManager, authCodeManager *manage.AuthorizationCodeManager) *AuthorizationCodeGrant {
	return &AuthorizationCodeGrant{
		clientManager:   clientManager,
		authCodeManager: authCodeManager,
	}
}

func (grant *AuthorizationCodeGrant) CheckResponseType(responseType ResponseType) bool {
	return responseType == ResponseTypeCode
}

func (grant *AuthorizationCodeGrant) ValidateRequest(r *AuthorizationRequest) error {
	clientID := r.ClientID
	if clientID == "" {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrDescMissingClientId),
			errors.WithState(r.State))
	}

	client, err := grant.clientManager.QueryByClientID(clientID)
	if err != nil {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrDescClientIDNotFound),
			errors.WithState(r.State))
	}

	redirectURI, err := grant.ValidateRedirectUri(r, client)
	if err != nil {
		return err
	}

	if !grant.CheckResponseType(r.ResponseType) {
		return errors.NewUnsupportedResponseTypeError(
			errors.WithState(r.State),
			errors.WithRedirectUri(redirectURI))
	}
	if allowed := client.CheckResponseType(string(r.ResponseType)); !allowed {
		return errors.NewUnauthorizedClientError(
			errors.WithState(r.State),
			errors.WithRedirectUri(redirectURI))
	}

	r.Client = client
	r.RedirectURI = redirectURI

	// TODO - Validate requested scopes
	return nil
}

func (grant *AuthorizationCodeGrant) Response(rw http.ResponseWriter, r *AuthorizationRequest) error {
	userID := r.UserID
	if userID == "" {
		return errors.NewAccessDeniedError(
			errors.WithState(r.State),
			errors.WithRedirectUri(r.RedirectURI))
	}

	authCode := grant.authCodeManager.Generate(GrantTypeAuthorizationCode, r.Client, userID)
	params := map[string]interface{}{
		Code: authCode.GetCode(),
	}
	if r.State != "" {
		params[State] = r.State
	}

	location, err := common.AddParamsToURI(r.RedirectURI, params)
	if err != nil {
		return err
	}

	rw.Header().Set(HeaderLocation, location)
	rw.WriteHeader(http.StatusFound)
	return nil
}
