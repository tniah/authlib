package rfc6749

import "net/http"

type AuthorizationRequest struct {
	ClientID     string
	ResponseType ResponseType
	RedirectURI  string
	Scope        string
	State        string
	Request      *http.Request
	Client       OAuthClient
}
