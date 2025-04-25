package requests

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
	"net/http"
	"strings"
)

type TokenRequest struct {
	GrantType   types.GrantType
	Code        string
	RedirectURI string
	ClientID    string
	Scopes      types.Scopes

	Username string
	Password string

	ClientAuthMethod types.ClientAuthMethod
	CodeVerifier     string

	Client   models.Client
	User     models.User
	AuthCode models.AuthorizationCode

	Request *http.Request
}

func NewTokenRequestFromHttp(r *http.Request) (*TokenRequest, error) {
	tokenReq := &TokenRequest{
		GrantType:    types.NewGrantType(r.PostFormValue("grant_type")),
		Code:         r.PostFormValue("code"),
		RedirectURI:  r.PostFormValue("redirect_uri"),
		ClientID:     r.PostFormValue("client_id"),
		Scopes:       types.NewScopes(strings.Fields(r.PostFormValue("scope"))),
		Username:     r.PostFormValue("username"),
		Password:     r.PostFormValue("password"),
		CodeVerifier: r.PostFormValue("code_verifier"),
		Request:      r,
	}

	return tokenReq, nil
}

func (r *TokenRequest) ValidateGrantType(required ...bool) error {
	if isRequired(true, required...) && r.GrantType.IsEmpty() {
		return autherrors.InvalidRequestError().WithDescription("missing \"grant_type\" in request")
	}

	return nil
}

func (r *TokenRequest) ValidateCode(required ...bool) error {
	if isRequired(true, required...) && r.Code == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"code\" in request")
	}

	return nil
}

func (r *TokenRequest) ValidateRedirectURI(required ...bool) error {
	if isRequired(true, required...) && r.RedirectURI == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"redirect_uri\" in request")
	}

	return nil
}

func (r *TokenRequest) ValidateUsername(required ...bool) error {
	if isRequired(true, required...) && r.Username == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"username\" in request")
	}

	return nil
}

func (r *TokenRequest) ValidatePassword(required ...bool) error {
	if isRequired(true, required...) && r.Password == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"password\" in request")
	}

	return nil
}

func (r *TokenRequest) Method() string {
	return r.Request.Method
}
