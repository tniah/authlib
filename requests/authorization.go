package requests

import (
	"github.com/tniah/authlib/models"
	"net/http"
	"strconv"
	"strings"
)

type AuthorizationRequest struct {
	ResponseType ResponseType
	ClientID     string
	RedirectURI  string
	Scopes       SpaceDelimitedArray
	State        string

	Nonce        string
	ResponseMode ResponseMode
	Display      Display
	Prompt       SpaceDelimitedArray
	MaxAge       *uint
	UILocales    Locales
	IDTokenHint  string
	LoginHint    string
	ACRValues    SpaceDelimitedArray

	CodeChallenge       string
	CodeChallengeMethod CodeChallengeMethod

	Client models.Client
	User   models.User

	Request *http.Request
}

func NewAuthorizationRequestFromHttp(r *http.Request) (*AuthorizationRequest, error) {
	authReq := &AuthorizationRequest{
		ResponseType:        ResponseType(r.FormValue("response_type")),
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scopes:              strings.Fields(r.FormValue("scopes")),
		State:               r.FormValue("state"),
		Nonce:               r.FormValue("nonce"),
		ResponseMode:        ResponseMode(r.FormValue("response_mode")),
		Display:             Display(r.FormValue("display")),
		Prompt:              strings.Fields(r.FormValue("prompt")),
		UILocales:           NewLocales(strings.Fields(r.FormValue("ui_locales"))),
		IDTokenHint:         r.FormValue("id_token_hint"),
		LoginHint:           r.FormValue("login_hint"),
		ACRValues:           strings.Fields(r.FormValue("acr_values")),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: CodeChallengeMethod(r.FormValue("code_challenge_method")),
		Request:             r,
	}

	maxAge, err := strconv.ParseUint(r.FormValue("max_age"), 10, 64)
	if err != nil {
		return nil, err
	}
	authReq.MaxAge = NewMaxAge(uint(maxAge))

	return authReq, nil
}
