package rfc6749

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
)

type ClientManager interface {
	QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
}

type AuthorizationCodeManager interface {
	Generate(grantType string, r *requests.AuthorizationRequest) (string, error)
}
