package manage

import (
	"context"
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/models"
)

type TokenStore interface {
	FetchByAccessToken(ctx context.Context, token string) (models.Token, error)
	FetchByRefreshToken(ctx context.Context, token string) (models.Token, error)
	Save(ctx context.Context, token models.Token) error
}

type TokenManager struct {
	store TokenStore
}

func NewTokenManager(store TokenStore) *TokenManager {
	return &TokenManager{store: store}
}

func (m *TokenManager) GenerateAccessToken(grantType constants.GrantType, user models.User, client models.Client, scopes []string) (models.Token, error) {
	return nil, nil
}

func (m *TokenManager) SaveAccessToken(ctx context.Context, token models.Token) error {
	return m.store.Save(ctx, token)
}
