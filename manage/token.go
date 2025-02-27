package manage

import (
	"context"
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
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

func (m *TokenManager) Generate(gt constants.GrantType, r *requests.TokenRequest) (models.Token, error) {
	return nil, nil
}

func (m *TokenManager) Save(ctx context.Context, token models.Token) error {
	return m.store.Save(ctx, token)
}
