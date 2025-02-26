package grants

import (
	"github.com/tniah/authlib/rfc6749/errors"
	"github.com/tniah/authlib/rfc6749/model"
	"github.com/tniah/authlib/rfc6749/request"
)

type AuthorizationGrantMixin struct{}

func (grant *AuthorizationGrantMixin) ValidateRedirectURI(r *request.AuthorizationRequest, client model.Client) (redirectURI string, err error) {
	if r.RedirectURI == "" {
		redirectURI = client.GetDefaultRedirectURI()
		if redirectURI == "" {
			return "", errors.NewInvalidRequestError(
				errors.WithDescription(ErrDescMissingRedirectURI),
				errors.WithState(r.State))
		}
	} else {
		redirectURI = r.RedirectURI
		if allowed := client.CheckRedirectURI(redirectURI); !allowed {
			return "", errors.NewInvalidRequestError(
				errors.WithDescription(ErrDescInvalidRedirectURI),
				errors.WithState(r.State))
		}
	}
	return redirectURI, nil
}
