package ropc

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"net/http"
)

type ClientManager interface {
	Authenticate(r *http.Request, supportedMethods map[types.ClientAuthMethod]bool, endpoint string) (models.Client, error)
}

type UserManager interface {
	Authenticate(username string, password string, client models.Client, r *http.Request) (models.User, error)
}

type TokenManager interface {
	New() models.Token
	Generate(token models.Token, r *requests.TokenRequest, includeRefreshToken bool) error
	Save(ctx context.Context, token models.Token) error
}

type TokenRequestValidator interface {
	ValidateTokenRequest(r *requests.TokenRequest) error
}

type TokenProcessor interface {
	ProcessToken(r *requests.TokenRequest, token models.Token, data map[string]interface{}) error
}
