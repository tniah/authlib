package requests

import (
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/models"
	"net/http"
)

type TokenRequest struct {
	GrantType               constants.GrantType
	ClientID                string
	Code                    string
	RedirectURI             string
	Scope                   string
	CodeChallenge           string
	CodeChallengeMethod     string
	CodeVerifier            string
	TokenEndpointAuthMethod constants.TokenEndpointAuthMethodType
	Client                  models.Client
	AuthorizationCode       models.AuthorizationCode
	Request                 *http.Request
}
