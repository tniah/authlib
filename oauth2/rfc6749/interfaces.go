package rfc6749

import "net/http"

type OAuth2Grant interface {
	RegisterWithServer(srv AuthorizationServer)
}

type AuthorizationRequestHandler interface {
	CheckResponseType(responseType ResponseType) bool
	ValidateAuthorizationRequest(r *AuthorizationRequest) error
	CreateAuthorizationResponse(rw http.ResponseWriter, r *AuthorizationRequest) error
}
