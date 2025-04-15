package ropc

import (
	"context"
	"github.com/tniah/authlib/models"
	"net/http"
)

type ClientManager interface {
	Authenticate(r *http.Request, supportedMethods map[string]bool, endpoint string) (models.Client, error)
}

type UserManager interface {
	Authenticate(username string, password string, client models.Client, r *http.Request) (models.User, error)
}

type TokenManager interface {
	New() models.Token
	Generate(grantType string, token models.Token, client models.Client, user models.User, scopes []string, includeRefreshToken bool) error
	Save(ctx context.Context, token models.Token) error
}
