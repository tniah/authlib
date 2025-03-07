package requests

import (
	"github.com/tniah/authlib/models"
	"net/http"
)

type TokenRequest struct {
	GrantType               string
	ClientID                string
	Code                    string
	RedirectURI             string
	Scopes                  []string
	CodeChallenge           string
	CodeChallengeMethod     string
	CodeVerifier            string
	TokenEndpointAuthMethod string
	Client                  models.Client
	AuthorizationCode       models.AuthorizationCode
	Request                 *http.Request
}
