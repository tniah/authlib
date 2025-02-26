package request

import (
	"github.com/tniah/authlib/rfc6749/model"
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
	Client              model.Client
	Request             *http.Request
}
