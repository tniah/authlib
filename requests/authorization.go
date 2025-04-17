package requests

import (
	"github.com/tniah/authlib/attributes"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"net/http"
	"strconv"
	"strings"
)

type AuthorizationRequest struct {
	GrantType    string
	ResponseType attributes.ResponseType
	ClientID     string
	RedirectURI  string
	Scopes       attributes.SpaceDelimitedArray
	State        string

	Nonce        string
	ResponseMode attributes.ResponseMode
	Display      attributes.Display
	Prompts      attributes.SpaceDelimitedArray
	MaxAge       *uint
	UILocales    attributes.Locales
	IDTokenHint  string
	LoginHint    string
	ACRValues    attributes.SpaceDelimitedArray

	CodeChallenge       string
	CodeChallengeMethod attributes.CodeChallengeMethod

	Client models.Client
	User   models.User

	Request *http.Request
}

func NewAuthorizationRequestFromHttp(r *http.Request) (*AuthorizationRequest, error) {
	authReq := &AuthorizationRequest{
		ResponseType:        attributes.ResponseType(r.FormValue("response_type")),
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scopes:              strings.Fields(r.FormValue("scope")),
		State:               r.FormValue("state"),
		Nonce:               r.FormValue("nonce"),
		ResponseMode:        attributes.ResponseMode(r.FormValue("response_mode")),
		Display:             attributes.Display(r.FormValue("display")),
		Prompts:             strings.Fields(r.FormValue("prompt")),
		UILocales:           attributes.NewLocales(strings.Fields(r.FormValue("ui_locales"))),
		IDTokenHint:         r.FormValue("id_token_hint"),
		LoginHint:           r.FormValue("login_hint"),
		ACRValues:           strings.Fields(r.FormValue("acr_values")),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: attributes.CodeChallengeMethod(r.FormValue("code_challenge_method")),
		Request:             r,
	}

	maxAge, err := strconv.ParseUint(r.FormValue("max_age"), 10, 64)
	if err != nil {
		return nil, err
	}
	authReq.MaxAge = attributes.NewMaxAge(uint(maxAge))

	return authReq, nil
}

func (r *AuthorizationRequest) ValidateResponseType(expected string, opts ...bool) error {
	if isRequired(true, opts...) && r.ResponseType == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingResponseType).WithState(r.State)
	}

	if r.ResponseType != "" && r.ResponseType != attributes.ResponseType(expected) {
		return autherrors.UnsupportedResponseTypeError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateClientID(opts ...bool) error {
	if isRequired(true, opts...) && r.ClientID == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingClientID).WithState(r.State)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateRedirectURI(opts ...bool) error {
	if isRequired(true, opts...) && r.RedirectURI == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingRedirectURI).WithState(r.State)
	}

	return nil
}

func (r *AuthorizationRequest) ContainOpenIDScope() bool {
	if r.Scopes == nil || len(r.Scopes) == 0 {
		return false
	}

	for _, scope := range r.Scopes {
		if scope == attributes.ScopeOpenID {
			return true
		}
	}

	return false
}

func (r *AuthorizationRequest) ValidateNonce(opts ...bool) error {
	if isRequired(true, opts...) && r.Nonce == "" {
		return autherrors.InvalidRequestError().
			WithDescription(ErrMissingNonce).
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateResponseMode(opts ...bool) error {
	if isRequired(false, opts...) && r.ResponseMode == "" {
		return autherrors.InvalidRequestError().
			WithDescription(ErrMissingResponseMode).
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateDisplay(opts ...bool) error {
	if isRequired(false, opts...) && r.Display == "" {
		return autherrors.InvalidRequestError().
			WithDescription(ErrMissingDisplay).
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	if r.Display != "" &&
		r.Display != attributes.DisplayPage &&
		r.Display != attributes.DisplayPopup &&
		r.Display != attributes.DisplayTouch &&
		r.Display != attributes.DisplayWap {
		return autherrors.InvalidRequestError().
			WithDescription(ErrInvalidDisplay).
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) ValidatePrompts(opts ...bool) error {
	if isRequired(false, opts...) && (r.Prompts == nil || len(r.Prompts) == 0) {
		return autherrors.InvalidRequestError().
			WithDescription(ErrMissingPrompt).
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	prompts := make(attributes.SpaceDelimitedArray, 0)
	for _, prompt := range r.Prompts {
		if prompt == attributes.PromptNone ||
			prompt == attributes.PromptLogin ||
			prompt == attributes.PromptConsent ||
			prompt == attributes.PromptSelectAccount {
			prompts = append(prompts, prompt)
		}
	}

	r.Prompts = prompts
	return nil
}
