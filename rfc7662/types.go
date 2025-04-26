package rfc7662

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
	"net/http"
)

type ClientManager interface {
	Authenticate(r *http.Request, authMethods map[types.ClientAuthMethod]bool, endpointName string) (models.Client, error)
	CheckPermission(client models.Client, token models.Token, r *http.Request) bool
}

type TokenManager interface {
	QueryByToken(ctx context.Context, token string, hint types.TokenTypeHint) (models.Token, error)
	Inspect(client models.Client, token models.Token) map[string]interface{}
}
