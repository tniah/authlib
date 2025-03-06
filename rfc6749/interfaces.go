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

type UserManager interface {
	GetByID(ctx context.Context, id string) (models.User, error)
}

type AuthorizationCodeManager interface {
	QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
	Generate(grantType constants.GrantType, r *requests.AuthorizationRequest) (models.AuthorizationCode, error)
	Save(ctx context.Context, authorizationCode models.AuthorizationCode) error
	DeleteByCode(ctx context.Context, code models.AuthorizationCode) error
}

type TokenManager interface {
	GenerateAccessToken(grantType constants.GrantType, user models.User, client models.Client, scopes []string) (models.Token, error)
	SaveAccessToken(ctx context.Context, token models.Token) error
}
