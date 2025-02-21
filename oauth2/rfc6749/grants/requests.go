package grants

import (
	"github.com/tniah/authlib/oauth2/rfc6749/models"
	"net/http"
)

type AuthorizationRequest struct {
	ResponseType ResponseType
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
	UserID       string
	Client       models.OAuthClient
	Request      *http.Request
}
