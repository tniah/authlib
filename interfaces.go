package authlib

import (
	"net/http"
)

type AuthorizationGrant interface {
	CheckResponseType(typ string) bool
	AuthorizationResponse(r *http.Request, rw http.ResponseWriter) error
}

type TokenGrant interface {
	CheckGrantType(gt string) bool
	TokenResponse(r *http.Request, rw http.ResponseWriter) error
}

type Endpoint interface {
	CheckEndpoint(name string) bool
	EndpointResponse(r *http.Request, rw http.ResponseWriter) error
}
