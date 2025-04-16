package requests

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"net/http"
	"strings"
)

type TokenRequest struct {
	GrantType   string
	Code        string
	RedirectURI string
	ClientID    string
	Scopes      []string

	Client   models.Client
	User     models.User
	AuthCode models.AuthorizationCode

	Request *http.Request
}

func NewTokenRequestFromHttp(r *http.Request) (*TokenRequest, error) {
	tokenReq := &TokenRequest{
		GrantType:   r.PostFormValue("grant_type"),
		Code:        r.PostFormValue("code"),
		RedirectURI: r.PostFormValue("redirect_uri"),
		ClientID:    r.PostFormValue("client_id"),
		Scopes:      strings.Fields(r.PostFormValue("scope")),
		Request:     r,
	}

	return tokenReq, nil
}

func (r *TokenRequest) ValidateGrantType(expected string, opts ...bool) error {
	if isRequired(true, opts...) && r.GrantType == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingGrantType)
	}

	if r.GrantType != expected {
		return autherrors.UnsupportedGrantTypeError()
	}

	return nil
}

func (r *TokenRequest) ValidateCode(opts ...bool) error {
	if isRequired(true, opts...) && r.Code == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingAuthorizationCode)
	}

	return nil
}

func (r *TokenRequest) ValidateRedirectURI(opts ...bool) error {
	if isRequired(true, opts...) && r.RedirectURI == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingRedirectURI)
	}

	return nil
}
