package rfc7662

import (
	"fmt"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
	"github.com/tniah/authlib/utils"
	"net/http"
)

const ()

type IntrospectionRequest struct {
	Token         string
	TokenTypeHint types.TokenTypeHint

	Client  models.Client
	Tok     models.Token
	Request *http.Request
}

func NewIntrospectionRequestFromHTTP(r *http.Request) *IntrospectionRequest {
	return &IntrospectionRequest{
		Token:         r.FormValue("token"),
		TokenTypeHint: types.NewTokenTypeHint(r.FormValue("token_type_hint")),
		Request:       r,
	}
}

func (r *IntrospectionRequest) ValidateHTTPMethod() error {
	if r.Request.Method != http.MethodPost {
		return autherrors.InvalidRequestError().WithDescription("request must be \"POST\"")
	}

	return nil
}

func (r *IntrospectionRequest) ValidateContentType() error {
	ct, err := utils.ContentType(r.Request)
	if err != nil {
		return autherrors.InvalidRequestError()
	}

	if valid := ct.IsXWWWFormUrlencoded(); !valid {
		return autherrors.InvalidRequestError().WithDescription("content type must be \"application/x-www-form-urlencoded\"")
	}

	return nil
}

func (r *IntrospectionRequest) ValidateToken() error {
	if r.Token == "" {
		return autherrors.InvalidRequestError().WithDescription("\"token\" is empty or missing")
	}

	return nil
}

func (r *IntrospectionRequest) ValidateTokenTypeHint() error {
	a := r.TokenTypeHint.IsEmpty()
	b := r.TokenTypeHint.IsValid()
	fmt.Println(a, b)
	if !r.TokenTypeHint.IsEmpty() && !r.TokenTypeHint.IsValid() {
		return autherrors.UnsupportedTokenType().
			WithDescription("token type hint must be set to \"access_token\" or \"refresh_token\"")
	}

	return nil
}
