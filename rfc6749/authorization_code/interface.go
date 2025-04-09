package authorizationcode

import (
	"context"
	"github.com/tniah/authlib/models"
	"net/http"
)

type ClientManager interface {
	FetchByClientID(ctx context.Context, clientID string) (models.Client, error)
	Authenticate(r *http.Request, supportedMethods map[string]bool, endpoint string) (models.Client, error)
}

type UserManager interface {
	Authenticate(r *http.Request, client models.Client) (models.User, error)
}

type AuthCodeManager interface {
	FetchByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
	Generate(grantType string, client models.Client, user models.User, r *http.Request) (models.AuthorizationCode, error)
	DeleteByCode(ctx context.Context, code string) error
}

type TokenManager interface {
	GenerateAccessToken(grantType string, client models.Client, user models.User, scopes []string, includeRefreshToken bool, r *http.Request) (models.Token, error)
}
