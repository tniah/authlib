package rfc7662

import (
	"context"
	"github.com/tniah/authlib/models"
	"net/http"
)

type (
	ClientManager interface {
		Authenticate(r *http.Request, authMethods map[string]bool, endpointName string) (models.Client, error)
		CheckPermission(client models.Client, token models.Token, r *http.Request) bool
	}

	TokenManager interface {
		QueryByToken(ctx context.Context, token, hint string) (models.Token, error)
		Inspect(client models.Client, token models.Token) map[string]interface{}
	}
)
