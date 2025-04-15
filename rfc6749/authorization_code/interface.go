package authorizationcode

import (
	"context"
	"github.com/tniah/authlib/models"
	"net/http"
)

type ClientManager interface {
	QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
	Authenticate(r *http.Request, authMethods map[string]bool, endpointName string) (models.Client, error)
}

type UserManager interface {
	QueryByUserID(ctx context.Context, userID string) (models.User, error)
	Authenticate(r *http.Request, client models.Client) (models.User, error)
}

type AuthCodeManager interface {
	New() models.AuthorizationCode
	QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
	Generate(grantType, responseType string, authCode models.AuthorizationCode, client models.Client, user models.User, scopes []string, redirectURI, state string, r *http.Request) error
	Save(ctx context.Context, code models.AuthorizationCode) error
	DeleteByCode(ctx context.Context, code string) error
}

type TokenManager interface {
	New() models.Token
	Generate(grantType string, token models.Token, client models.Client, user models.User, scopes []string, includeRefreshToken bool) error
	Save(ctx context.Context, token models.Token) error
}
