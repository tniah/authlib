package ropc

import (
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
	GenerateAccessToken(r *http.Request, grantType string, client models.Client, user models.User, scopes []string, includeRefreshToken bool) (models.Token, error)
}
