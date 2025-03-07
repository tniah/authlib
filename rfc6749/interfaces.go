package rfc6749

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"net/http"
)

type ClientManager interface {
	QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
	Authenticate(r *http.Request) (models.Client, string, error)
}

type UserManager interface {
	GetByID(ctx context.Context, id string) (models.User, error)
}

type AuthorizationCodeManager interface {
	QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
	Generate(grantType string, r *requests.AuthorizationRequest) (string, error)
	DeleteByCode(ctx context.Context, code models.AuthorizationCode) error
}

type TokenManager interface {
	GenerateAccessToken(grantType string, r *requests.TokenRequest, includeRefreshToken bool) (map[string]interface{}, error)
}
