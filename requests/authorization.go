package requests

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"net/http"
	"strconv"
	"strings"
)

const (
	ErrMissingClientID     = "missing \"client_id\" in request"
	ErrMissingRedirectURI  = "missing \"redirect_uri\" in request"
	ErrMissingNonce        = "missing \"nonce\" in request"
	ErrMissingResponseMode = "missing \"response_mode\" in request"
	ErrMissingResponseType = "missing \"response_type\" in request"
	ErrMissingDisplay      = "missing \"display\" in request"
	ErrInvalidDisplay      = "invalid \"display\" in request"
)

type AuthorizationRequest struct {
	GrantType    string
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

func (r *AuthorizationRequest) ValidateResponseType(expected string, opts ...bool) error {
	if r.isRequired(true, opts...) && r.ResponseType == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingResponseType).WithState(r.State)
	}

	if r.ResponseType != "" && r.ResponseType != ResponseType(expected) {
		return autherrors.UnsupportedResponseTypeError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateClientID(opts ...bool) error {
	if r.isRequired(true, opts...) && r.ClientID == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingClientID).WithState(r.State)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateRedirectURI(opts ...bool) error {
	if r.isRequired(true, opts...) && r.RedirectURI == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingRedirectURI).WithState(r.State)
	}

	return nil
}

func (r *AuthorizationRequest) ContainOpenIDScope() bool {
	if r.Scopes == nil || len(r.Scopes) == 0 {
		return false
	}

	for _, scope := range r.Scopes {
		if scope == ScopeOpenID {
			return true
		}
	}

	return false
}

func (r *AuthorizationRequest) ValidateNonce(opts ...bool) error {
	if r.isRequired(true, opts...) && r.Nonce == "" {
		return autherrors.InvalidRequestError().
			WithDescription(ErrMissingNonce).
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateResponseMode(opts ...bool) error {
	if r.isRequired(false, opts...) && r.ResponseMode == "" {
		return autherrors.InvalidRequestError().
			WithDescription(ErrMissingResponseMode).
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) ValidateDisplay(opts ...bool) error {
	if r.isRequired(false, opts...) && r.Display == "" {
		return autherrors.InvalidRequestError().
			WithDescription(ErrMissingDisplay).
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	if r.Display != "" &&
		r.Display != DisplayPage &&
		r.Display != DisplayPopup &&
		r.Display != DisplayTouch &&
		r.Display != DisplayWap {
		return autherrors.InvalidRequestError().
			WithDescription(ErrInvalidDisplay).
			WithState(r.State).
			WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (r *AuthorizationRequest) isRequired(defaultValue bool, opts ...bool) bool {
	if len(opts) > 0 {
		return opts[0]
	}

	return defaultValue
}
