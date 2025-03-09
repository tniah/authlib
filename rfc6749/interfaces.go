package rfc6749

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"net/http"
)

type (
	QueryClient func(ctx context.Context, clientID string) (models.Client, error)

	AuthenticateClient func(r *http.Request) (models.Client, string, error)

	QueryUser func(ctx context.Context, userID string) (models.User, error)

	AuthenticateUser func(username string, password string) (models.User, error)

	QueryAuthCode func(ctx context.Context, code string) (models.AuthorizationCode, error)

	GenerateAuthCode func(grantType string, r *requests.AuthorizationRequest) (models.AuthorizationCode, error)

	DeleteAuthCode func(ctx context.Context, code string) error

	GenerateAccessToken func(grantType string, r *requests.TokenRequest, includeRefreshToken bool) (models.Token, error)
)
