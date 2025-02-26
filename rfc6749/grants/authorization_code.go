package grants

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/rfc6749/errors"
	"github.com/tniah/authlib/rfc6749/request"
	"net/http"
)

const (
	responseTypeCode           = "code"
	grantTypeAuthorizationCode = "authorization_code"
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
	return responseType == responseTypeCode
}

func (grant *AuthorizationCodeGrant) ValidateRequest(r *request.AuthorizationRequest) error {
	clientID := r.ClientID
	state := r.State

	if clientID == "" {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrDescMissingClientID),
			errors.WithState(state))
	}

	client, err := grant.clientMgr.QueryByClientID(clientID)
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

func (grant *AuthorizationCodeGrant) Response(rw http.ResponseWriter, r *request.AuthorizationRequest) error {
	if r.UserID == "" {
		return errors.NewAccessDeniedError(
			errors.WithState(r.State),
			errors.WithRedirectURI(r.RedirectURI))
	}

	code, err := grant.authCodeMgr.Generate(grantTypeAuthorizationCode, r)
	if err != nil {
		return err
	}

	params := map[string]interface{}{
		Code: code,
	}
	if r.State != "" {
		params[State] = r.State
	}

	return common.Redirect(rw, r.RedirectURI, params)
}
