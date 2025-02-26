package grants

import (
	"github.com/tniah/authlib/oauth2/rfc6749/errors"
)

type AuthorizationGrantMixin struct{}

func (grant *AuthorizationGrantMixin) ValidateRedirectURI(r AuthorizationRequest, client OAuthClient) (RedirectURI string, err error) {
	RedirectURI = r.RedirectURI()
	state := r.State()
	if RedirectURI == "" {
		RedirectURI = client.GetDefaultRedirectURI()
		if RedirectURI == "" {
			return "", errors.NewInvalidRequestError(
				errors.WithDescription(ErrDescMissingRedirectURI),
				errors.WithState(state))
		}
	} else {
		if allowed := client.CheckRedirectURI(RedirectURI); !allowed {
			return "", errors.NewInvalidRequestError(
				errors.WithDescription(ErrDescInvalidRedirectURI),
				errors.WithState(state))
		}
	}
	return RedirectURI, nil
}
