package grants

import (
	"github.com/tniah/authlib/oauth2/rfc6749"
	"github.com/tniah/authlib/oauth2/rfc6749/errors"
	"net/http"
)

type AuthorizationGrant interface {
	CheckResponseType(responseType ResponseType) bool
	ValidateRequest(r *AuthorizationRequest) error
	Response(rw http.ResponseWriter, r *AuthorizationRequest) error
}

type AuthorizationGrantMixin struct{}

func (grant *AuthorizationGrantMixin) ValidateRedirectUri(r *AuthorizationRequest, client rfc6749.OAuthClient) (redirectURI string, err error) {
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
