package rfc7662

import (
	"context"
	"github.com/tniah/authlib/models"
	"net/http"
)

type ClientManager interface {
	Authenticate(r *http.Request, authMethods map[string]bool, endpointName string) (models.Client, error)
	CheckPermission(client models.Client, token models.Token, r *http.Request) bool
}

type TokenManager interface {
	QueryByToken(ctx context.Context, token, hint string) (models.Token, error)
	Inspect(client models.Client, token models.Token) map[string]interface{}
}

type TokenTypeHint string

func NewTokenTypeHint(s string) TokenTypeHint {
	return TokenTypeHint(s)
}

func (t TokenTypeHint) IsEmpty() bool {
	return t == ""
}

func (t TokenTypeHint) IsAccessToken() bool {
	return t == TokenTypeHintAccessToken
}

func (t TokenTypeHint) IsRefreshToken() bool {
	return t == TokenTypeHintRefreshToken
}

func (t TokenTypeHint) IsValid() bool {
	return t.IsAccessToken() || t.IsRefreshToken()
}

func (t TokenTypeHint) String() string {
	return string(t)
}
