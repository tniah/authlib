package rfc6749

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"net/http"
)

type (
	ClientQueryHandler func(ctx context.Context, clientID string) (models.Client, error)

	ClientAuthenticationHandler func(r *http.Request, supportedMethods map[string]bool, endpoint string) (models.Client, error)

	UserQueryHandler func(ctx context.Context, userID string) (models.User, error)

	AuthenticateUser func(username string, password string) (models.User, error)

	QueryAuthCode func(ctx context.Context, code string) (models.AuthorizationCode, error)

	GenerateAuthCode func(grantType string, r *requests.AuthorizationRequest) (models.AuthorizationCode, error)

	DeleteAuthCode func(ctx context.Context, code string) error

	AccessTokenGenerator func(r *http.Request, grantType string, client models.Client, user models.User, scopes []string, includeRefreshToken bool) (models.Token, error)
)
