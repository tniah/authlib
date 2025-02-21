package grants

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/oauth2/rfc6749/errors"
	"github.com/tniah/authlib/oauth2/rfc6749/manage"
	"github.com/tniah/authlib/oauth2/rfc6749/models"
	"net/http"
)

type AuthorizationCodeGrant struct {
	clientManager   *manage.ClientManager
	authCodeManager *manage.AuthorizationCodeManager
}

func NewAuthorizationCodeGrant(clientManager *manage.ClientManager, authCodeManager *manage.AuthorizationCodeManager) *AuthorizationCodeGrant {
	return &AuthorizationCodeGrant{
		clientManager:   clientManager,
		authCodeManager: authCodeManager,
	}
}

func (gt *AuthorizationCodeGrant) CheckResponseType(responseType ResponseType) bool {
	return responseType == ResponseTypeCode
}

func (gt *AuthorizationCodeGrant) ValidateAuthorizationRequest(r *AuthorizationRequest) error {
	clientID := r.ClientID
	if clientID == "" {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrDescMissingClientId),
			errors.WithState(r.State))
	}

	client, err := gt.clientManager.QueryByClientID(clientID)
	if err != nil {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrDescClientIDNotFound),
			errors.WithState(r.State))
	}

	redirectURI, err := validateRedirectUri(r, client)
	if err != nil {
		return err
	}

	if !gt.CheckResponseType(r.ResponseType) {
		return errors.NewUnsupportedResponseTypeError(
			errors.WithState(r.State),
			errors.WithRedirectUri(redirectURI))
	}
	if allowed := client.CheckResponseType(r.ResponseType); !allowed {
		return errors.NewUnauthorizedClientError(
			errors.WithState(r.State),
			errors.WithRedirectUri(redirectURI))
	}

	r.Client = client
	r.RedirectURI = redirectURI

	// TODO - Validate requested scopes
	return nil
}

func (gt *AuthorizationCodeGrant) CreateAuthorizationResponse(
	rw http.ResponseWriter,
	r *AuthorizationRequest,
) error {
	userID := r.UserID
	if userID == "" {
		return errors.NewAccessDeniedError(
			errors.WithState(r.State),
			errors.WithRedirectUri(r.RedirectURI))
	}

	authCode := gt.authCodeManager.Generate(GrantTypeAuthorizationCode, r.Client, userID)
	params := map[string]interface{}{
		"code": authCode.GetCode(),
	}
	if r.State != "" {
		params["state"] = r.State
	}

	uri, err := common.AddParamsToURI(r.RedirectURI, params)
	if err != nil {
		return err
	}

	rw.Header().Set("Location", uri)
	rw.WriteHeader(http.StatusFound)
	return nil
}

func validateRedirectUri(r *AuthorizationRequest, client models.OAuthClient) (redirectURI string, err error) {
	if r.RedirectURI == "" {
		redirectURI = client.GetDefaultRedirectURI()
		if redirectURI == "" {
			return "", errors.NewInvalidRequestError(
				errors.WithDescription(ErrDescMissingRedirectUri),
				errors.WithState(r.State))
		}
	} else {
		redirectURI = r.RedirectURI
		if allowed := client.CheckRedirectURI(redirectURI); !allowed {
			return "", errors.NewInvalidRequestError(
				errors.WithDescription(ErrDescInvalidRedirectUri),
				errors.WithState(r.State))
		}
	}

	return redirectURI, nil
}
