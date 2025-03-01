package rfc6749

import (
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
)

type AuthorizationGrantMixin struct{}

func (grant *AuthorizationGrantMixin) ValidateRedirectURI(r *requests.AuthorizationRequest, client models.Client) (redirectURI string, err error) {
	if r.RedirectURI == "" {
		redirectURI = client.GetDefaultRedirectURI()
		if redirectURI == "" {
			return "", errors.NewInvalidRequestError(
				errors.WithDescription(ErrMissingRedirectURI),
				errors.WithState(r.State))
		}
	} else {
		redirectURI = r.RedirectURI
		if allowed := client.CheckRedirectURI(redirectURI); !allowed {
			return "", errors.NewInvalidRequestError(
				errors.WithDescription(ErrUnsupportedRedirectURI),
				errors.WithState(r.State))
		}
	}
	return redirectURI, nil
}

type TokenGrantMixin struct{}
