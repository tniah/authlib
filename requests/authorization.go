package requests

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
	"net/http"
	"strconv"
	"strings"
)

type AuthorizationRequest struct {
	GrantType    types.GrantType
	ResponseType types.ResponseType
	ClientID     string
	RedirectURI  string
	Scopes       []types.Scope
	State        string

	Nonce        string
	ResponseMode types.ResponseMode
	Display      types.Display
	Prompts      []types.Prompt
	MaxAge       types.MaxAge
	UILocales    types.Locales
	IDTokenHint  string
	LoginHint    string
	ACRValues    types.SpaceDelimitedArray

	CodeChallenge       string
	CodeChallengeMethod types.CodeChallengeMethod

	Client models.Client
	User   models.User

	Request *http.Request
}

func NewAuthorizationRequestFromHttp(r *http.Request) (*AuthorizationRequest, error) {
	authReq := &AuthorizationRequest{
		ResponseType:        types.NewResponseType(r.FormValue("response_type")),
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scopes:              types.NewScopes(strings.Fields(r.FormValue("scope"))),
		State:               r.FormValue("state"),
		Nonce:               r.FormValue("nonce"),
		ResponseMode:        types.NewResponseMode(r.FormValue("response_mode")),
		Display:             types.NewDisplay(r.FormValue("display")),
		Prompts:             types.NewPrompts(strings.Fields(r.FormValue("prompt"))),
		UILocales:           types.NewLocales(strings.Fields(r.FormValue("ui_locales"))),
		IDTokenHint:         r.FormValue("id_token_hint"),
		LoginHint:           r.FormValue("login_hint"),
		ACRValues:           strings.Fields(r.FormValue("acr_values")),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: types.NewCodeChallengeMethod(r.FormValue("code_challenge_method")),
		Request:             r,
	}

	maxAge, err := strconv.ParseUint(r.FormValue("max_age"), 10, 64)
	if err != nil {
		return nil, err
	}
	authReq.MaxAge = types.NewMaxAge(uint(maxAge))

	return authReq, nil
}

func (r *AuthorizationRequest) ValidateResponseType(required ...bool) error {
	if isRequired(true, required...) && r.ResponseType.IsEmpty() {
		return autherrors.InvalidRequestError().WithDescription("missing \"response_type\" in request").WithState(r.State)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateClientID(required ...bool) error {
	if isRequired(true, required...) && r.ClientID == "" {
		return autherrors.InvalidRequestError().
			WithDescription("missing \"client_id\" in request").
			WithState(r.State)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateRedirectURI(required ...bool) error {
	if isRequired(true, required...) && r.RedirectURI == "" {
		return autherrors.InvalidRequestError().
			WithDescription("missing \"redirect_uri\" in request").
			WithState(r.State)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateNonce(required ...bool) error {
	if isRequired(true, required...) && r.Nonce == "" {
		return autherrors.InvalidRequestError().
			WithDescription("missing \"nonce\" in request").
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateResponseMode(required ...bool) error {
	if isRequired(false, required...) && r.ResponseMode.IsEmpty() {
		return autherrors.InvalidRequestError().
			WithDescription("missing \"response_mode\" in request").
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateDisplay(required ...bool) error {
	if isRequired(false, required...) && r.Display.IsEmpty() {
		return autherrors.InvalidRequestError().
			WithDescription("missing \"display\" in request").
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	if r.Display.IsEmpty() || !r.Display.IsValid() {
		r.Display = types.DisplayPage
	}

	return nil
}

func (r *AuthorizationRequest) ValidatePrompts(required ...bool) error {
	if isRequired(false, required...) && len(r.Prompts) == 0 {
		return autherrors.InvalidRequestError().
			WithDescription("missing \"prompt\" in request").
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) Method() string {
	return r.Request.Method
}
