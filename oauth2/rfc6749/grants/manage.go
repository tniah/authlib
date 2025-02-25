package grants

import (
	"context"
)

type ClientManager interface {
	QueryByClientId(ctx context.Context, ClientID string) (OAuthClient, error)
}

type AuthorizationCodeManager interface {
	Generate(gt GrantType, client OAuthClient, userID string) AuthorizationCode
}
