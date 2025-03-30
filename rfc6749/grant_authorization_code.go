package rfc6749

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"net/http"
)

type AuthorizationCodeGrant struct {
	mgr *AuthCodeGrantManager
	*TokenGrantMixin
}

func NewAuthorizationCodeGrant(mgr *AuthCodeGrantManager) *AuthorizationCodeGrant {
	return &AuthorizationCodeGrant{mgr: mgr}
}

func MustAuthorizationCodeGrant(mgr *AuthCodeGrantManager) *AuthorizationCodeGrant {
	if err := mgr.Validate(); err != nil {
		panic(err)
	}

	return NewAuthorizationCodeGrant(mgr)
}

func (grant *AuthorizationCodeGrant) CheckGrantType(gt string) bool {
	return gt == GrantTypeAuthorizationCode
}

func (grant *AuthorizationCodeGrant) CheckResponseType(rt string) bool {
	return rt == ResponseTypeCode
}

func (grant *AuthorizationCodeGrant) CheckClient(r *http.Request, state string) (client models.Client, err error) {
	clientID := r.URL.Query().Get(ParamClientID)
	if clientID == "" {
		return nil, autherrors.InvalidRequestError().WithDescription(ErrMissingClientID).WithState(state)
	}

	if client, err = grant.mgr.clientQueryHandler(r.Context(), clientID); err != nil {
		return nil, err
	}

	if client == nil {
		return nil, autherrors.InvalidRequestError().WithDescription(ErrClientIDNotFound).WithState(state)
	}

	return client, nil
}

func (grant *AuthorizationCodeGrant) ValidateRedirectURI(r *http.Request, client models.Client, state string) (string, error) {
	redirectURI := r.URL.Query().Get(ParamRedirectURI)
	if redirectURI == "" {
		redirectURI = client.GetDefaultRedirectURI()

		if redirectURI == "" {
			return "", autherrors.InvalidRequestError().WithDescription(ErrMissingRedirectURI).WithState(state)
		}

		return redirectURI, nil
	}

	if allowed := client.CheckRedirectURI(redirectURI); !allowed {
		return "", autherrors.InvalidRequestError().WithDescription(ErrUnsupportedRedirectURI).WithState(state)
	}

	return redirectURI, nil
}

func (grant *AuthorizationCodeGrant) ValidateResponseType(r *http.Request, client models.Client, redirectURI, state string) error {
	responseType := r.URL.Query().Get(ParamResponseType)
	if responseType == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingResponseType).WithRedirectURI(redirectURI).WithState(state)
	}

	if !grant.CheckResponseType(responseType) {
		return autherrors.UnsupportedResponseTypeError().WithRedirectURI(redirectURI).WithState(state)
	}

	if allowed := client.CheckResponseType(responseType); !allowed {
		return autherrors.UnauthorizedClientError().WithRedirectURI(redirectURI).WithState(state)
	}

	return nil
}

func (grant *AuthorizationCodeGrant) ValidateAuthorizationRequest(r *http.Request) (client models.Client, redirectURI string, err error) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return nil, "", autherrors.InvalidRequestError().WithDescription(ErrRequestMustBeGetOrPost)
	}

	state := r.URL.Query().Get(ParamState)
	if client, err = grant.CheckClient(r, state); err != nil {
		return nil, "", err
	}

	redirectURI, err = grant.ValidateRedirectURI(r, client, state)
	if err != nil {
		return nil, "", err
	}

	if err = grant.ValidateResponseType(r, client, redirectURI, state); err != nil {
		return nil, "", err
	}

	return client, redirectURI, nil
}
