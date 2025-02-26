package grants

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/oauth2/rfc6749/errors"
	"net/http"
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
	return ResponseType(responseType) == ResponseTypeCode
}

func (grant *AuthorizationCodeGrant) ValidateRequest(r AuthorizationRequest) error {
	ClientID := r.ClientID()
	state := r.State()

	if ClientID == "" {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrDescMissingClientID),
			errors.WithState(state))
	}

	client, err := grant.clientMgr.QueryByClientID(r.Request().Context(), ClientID)
	if err != nil {
		return errors.NewInvalidRequestError(
			errors.WithDescription(ErrDescClientIDNotFound),
			errors.WithState(state))
	}

	RedirectURI, err := grant.ValidateRedirectURI(r, client)
	if err != nil {
		return err
	}

	responseType := r.ResponseType()
	if !grant.CheckResponseType(responseType) {
		return errors.NewUnsupportedResponseTypeError(
			errors.WithState(state),
			errors.WithRedirectURI(RedirectURI))
	}
	if allowed := client.CheckResponseType(r.ResponseType()); !allowed {
		return errors.NewUnauthorizedClientError(
			errors.WithState(state),
			errors.WithRedirectURI(RedirectURI))
	}

	r.SetClient(client)
	r.SetRedirectURI(RedirectURI)

	// TODO - Validate requested scopes
	return nil
}

func (grant *AuthorizationCodeGrant) Response(rw http.ResponseWriter, r AuthorizationRequest) error {
	UserID := r.UserID()
	state := r.State()
	RedirectURI := r.RedirectURI()

	if UserID == "" {
		return errors.NewAccessDeniedError(
			errors.WithState(state),
			errors.WithRedirectURI(RedirectURI))
	}

	authCode, err := grant.authCodeMgr.Generate(GrantTypeAuthorizationCode, r)
	if err != nil {
		return err
	}

	params := map[string]interface{}{
		Code: authCode.GetCode(),
	}
	if state != "" {
		params[State] = r.State
	}

	return common.Redirect(rw, RedirectURI, params)
}
