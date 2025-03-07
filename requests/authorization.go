package requests

import (
	"github.com/tniah/authlib/models"
	"net/http"
)

type AuthorizationRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	Nonce               string
	State               string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod string
	Client              models.Client
	Request             *http.Request
}
