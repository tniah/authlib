package rfc6749

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/requests"
	"net/http"
)

const (
	ErrDescMissingClientID    = "Missing \"client_id\" parameter in request"
	ErrDescClientIDNotFound   = "No client was found that matches \"client_id\" value"
	ErrDescMissingRedirectURI = "Missing \"redirect_uri\" parameter in request"
	ErrDescInvalidRedirectURI = "Redirect URI is not supported by client"
)

type AuthorizationCodeGrant struct {
	clientMgr   ClientManager
	authCodeMgr AuthorizationCodeManager
	AuthorizationGrantMixin
}

func NewAuthorizationCodeGrant(clientMgr ClientManager, authCodeMgr AuthorizationCodeManager) *AuthorizationCodeGrant {
	return &AuthorizationCodeGrant{
		clientMgr:   clientMgr,
		authCodeMgr: authCodeMgr,
	}
}

func (grant *AuthorizationCodeGrant) CheckResponseType(responseType string) bool {
	return constants.ResponseType(responseType) == constants.ResponseTypeCode
}

func (grant *AuthorizationCodeGrant) ValidateRequest(r *requests.AuthorizationRequest) error {
	clientID := r.ClientID
	state := r.State

	if clientID == "" {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrDescMissingClientID),
			errors.WithState(state))
	}

	client, err := grant.clientMgr.QueryByClientID(r.Request.Context(), clientID)
	if err != nil {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrDescClientIDNotFound),
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

func (grant *AuthorizationCodeGrant) Response(rw http.ResponseWriter, r *requests.AuthorizationRequest) error {
	if r.UserID == "" {
		return errors.NewAccessDeniedError(
			errors.WithState(r.State),
			errors.WithRedirectURI(r.RedirectURI))
	}

	code, err := grant.authCodeMgr.Generate(constants.GrantTypeAuthorizationCode, r)
	if err != nil {
		return err
	}

	params := map[string]interface{}{
		constants.QueryParamCode: code,
	}
	if r.State != "" {
		params[constants.QueryParamState] = r.State
	}

	return common.Redirect(rw, r.RedirectURI, params)
}
