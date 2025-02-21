package grants

import (
	"github.com/tniah/authlib/oauth2/rfc6749"
	"net/http"
)

type AuthorizationCodeGrant struct {
	server rfc6749.AuthorizationServer
}

func NewAuthorizationCodeHandler() *AuthorizationCodeGrant {
	return &AuthorizationCodeGrant{}
}

func (gt *AuthorizationCodeGrant) RegisterWithServer(srv rfc6749.AuthorizationServer) {
	gt.server = srv
}

func (gt *AuthorizationCodeGrant) CheckResponseType(responseType rfc6749.ResponseType) bool {
	return responseType == rfc6749.ResponseTypeCode
}

func (gt *AuthorizationCodeGrant) ValidateAuthorizationRequest(r *rfc6749.AuthorizationRequest) error {
	clientID := r.ClientID
	if clientID == "" {
		return rfc6749.NewInvalidRequestError(
			rfc6749.WithDescription(ErrDescMissingClientId),
			rfc6749.WithState(r.State))
	}

	client := gt.server.QueryClient(clientID)
	if client == nil {
		return rfc6749.NewInvalidRequestError(
			rfc6749.WithDescription(ErrDescClientIDNotFound),
			rfc6749.WithState(r.State))
	}

	redirectURI, err := validateRedirectUri(r, client)
	if err != nil {
		return err
	}

	if allowed := client.CheckResponseType(r.ResponseType); !allowed {
		return rfc6749.NewUnauthorizedClientError(
			rfc6749.WithState(r.State),
			rfc6749.WithRedirectUri(redirectURI))
	}

	r.Client = client
	r.RedirectURI = redirectURI
	return nil
}

func (gt *AuthorizationCodeGrant) CreateAuthorizationResponse(
	rw http.ResponseWriter,
	r *rfc6749.AuthorizationRequest,
) error {
	return nil
}

func validateRedirectUri(r *rfc6749.AuthorizationRequest, client rfc6749.OAuthClient) (redirectURI string, err error) {
	if r.RedirectURI == "" {
		redirectURI = client.GetDefaultRedirectUri()
		if redirectURI == "" {
			return "", rfc6749.NewInvalidRequestError(
				rfc6749.WithDescription(ErrDescMissingRedirectUri),
				rfc6749.WithState(r.State))
		}
	} else {
		redirectURI = r.RedirectURI
		if allowed := client.CheckRedirectUri(redirectURI); !allowed {
			return "", rfc6749.NewInvalidRequestError(
				rfc6749.WithDescription(ErrDescInvalidRedirectUri),
				rfc6749.WithState(r.State))
		}
	}

	return redirectURI, nil
}
