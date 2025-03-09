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
	Username                string
	Password                string
	Client                  models.Client
	User                    models.User
	AuthorizationCode       models.AuthorizationCode
	Request                 *http.Request
}
