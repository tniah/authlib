package rfc6749

import (
	"context"
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"net/http"
)

type ClientManager interface {
	QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
	Authenticate(r *http.Request) (models.Client, constants.TokenEndpointAuthMethodType, error)
}

type AuthorizationCodeManager interface {
	QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
	Generate(grantType constants.GrantType, r *requests.AuthorizationRequest) (string, error)
}
