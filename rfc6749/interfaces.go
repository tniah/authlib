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
	GetByID(ctx context.Context, userID string) (models.User, error)
}

type AuthorizationCodeManager interface {
	QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
	Generate(grantType string, r *requests.AuthorizationRequest) (models.AuthorizationCode, error)
	DeleteByCode(ctx context.Context, code string) error
}

type TokenManager interface {
	GenerateAccessToken(grantType string, r *requests.TokenRequest, includeRefreshToken bool) (models.Token, error)
}

type (
	QueryByClientID func(ctx context.Context, clientID string) (models.Client, error)

	ClientAuthenticationHandler func(r *http.Request) (models.Client, string, error)

	UserAuthenticationHandler func(username string, password string) (models.User, error)

	AccessTokenGenerator func(grantType string, r *requests.TokenRequest, includeRefreshToken bool) (models.Token, error)
)
