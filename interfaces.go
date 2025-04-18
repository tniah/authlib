package authlib

import (
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"net/http"
)

type AuthorizationGrant interface {
	CheckResponseType(typ string) bool
	ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error
	AuthorizationResponse(r *requests.AuthorizationRequest, rw http.ResponseWriter) error
}

type ConsentGrant interface {
	CheckResponseType(typ string) bool
	ValidateConsentRequest(r *requests.AuthorizationRequest) error
	AuthorizationResponse(r *requests.AuthorizationRequest, rw http.ResponseWriter) error
}

type TokenGrant interface {
	CheckGrantType(gt types.GrantType) bool
	ValidateTokenRequest(r *requests.TokenRequest) error
	TokenResponse(r *requests.TokenRequest, rw http.ResponseWriter) error
}

type Endpoint interface {
	CheckEndpoint(name string) bool
	EndpointResponse(r *http.Request, rw http.ResponseWriter) error
}
