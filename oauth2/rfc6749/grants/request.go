package grants

import (
	"net/http"
)

type AuthorizationRequest struct {
	ResponseType ResponseType
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
	UserID       string
	Client       OAuthClient
	Request      *http.Request
}
