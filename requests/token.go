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

	Client models.Client
	User   models.User

	Request *http.Request
}

func NewTokenRequestFromHttp(r *http.Request) (*TokenRequest, error) {
	tokenReq := &TokenRequest{
		GrantType:   r.FormValue("grant_type"),
		Code:        r.FormValue("code"),
		RedirectURI: r.FormValue("redirect_uri"),
		ClientID:    r.FormValue("client_id"),
		Scopes:      strings.Fields(r.FormValue("scope")),
		Request:     r,
	}

	return tokenReq, nil
}

func (r *TokenRequest) ValidateGrantType(expected string, opts ...bool) error {
	if isRequired(true, opts...) && r.GrantType == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingGrantType)
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
