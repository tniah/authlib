package authlib

import (
	"github.com/tniah/authlib/requests"
	"net/http"
)

type AuthorizationGrant interface {
	CheckResponseType(responseType string) bool
	ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error
	AuthorizationResponse(rw http.ResponseWriter, r *requests.AuthorizationRequest) error
}

type TokenGrant interface {
	CheckGrantType(grantType string) bool
	ValidateTokenRequest(r *requests.TokenRequest) error
	TokenResponse(rw http.ResponseWriter, r *requests.TokenRequest) error
}
