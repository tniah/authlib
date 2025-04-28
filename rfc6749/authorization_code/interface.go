package authorizationcode

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"net/http"
)

type ClientManager interface {
	QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
	Authenticate(r *http.Request, authMethods map[types.ClientAuthMethod]bool, endpointName string) (models.Client, error)
}

type UserManager interface {
	QueryByUserID(ctx context.Context, userID string) (models.User, error)
}

type AuthCodeManager interface {
	New() models.AuthorizationCode
	QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
	Generate(authCode models.AuthorizationCode, r *requests.AuthorizationRequest) error
	Save(ctx context.Context, code models.AuthorizationCode) error
	DeleteByCode(ctx context.Context, code string) error
}

type TokenManager interface {
	New() models.Token
	Generate(token models.Token, r *requests.TokenRequest, includeRefreshToken bool) error
	Save(ctx context.Context, token models.Token) error
}

type AuthorizationRequestValidator interface {
	ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error
}

type ConsentRequestValidator interface {
	ValidateConsentRequest(r *requests.AuthorizationRequest) error
}

type AuthCodeProcessor interface {
	ProcessAuthorizationCode(r *requests.AuthorizationRequest, authCode models.AuthorizationCode, params map[string]interface{}) error
}

type TokenRequestValidator interface {
	ValidateTokenRequest(r *requests.TokenRequest) error
}

type TokenProcessor interface {
	ProcessToken(r *requests.TokenRequest, token models.Token, data map[string]interface{}) error
}
