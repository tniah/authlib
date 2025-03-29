package rfc7662

import (
	"context"
	"github.com/tniah/authlib/models"
	"net/http"
)

type (
	ClientAuthHandler func(r *http.Request, authMethods map[string]bool, endpointName string) (models.Client, error)

	ClientPermissionHandler func(r *http.Request, client models.Client, token models.Token) bool

	TokenQueryHandler func(ctx context.Context, token string, hint string) (models.Token, error)

	TokenIntrospectionHandler func(token models.Token) map[string]interface{}
)
