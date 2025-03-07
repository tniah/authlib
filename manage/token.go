package manage

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/rfc6750"
)

type (
	TokenManager struct {
		store                TokenStore
		bearerTokenGenerator *rfc6750.BearerTokenGenerator
	}

	TokenStore interface {
		Save(ctx context.Context, token models.Token) error
	}
)

func NewTokenManager(store TokenStore) *TokenManager {
	bearerTokenGenerator := rfc6750.NewBearerTokenGenerator()
	return &TokenManager{
		store:                store,
		bearerTokenGenerator: bearerTokenGenerator,
	}
}

func (m *TokenManager) GenerateAccessToken(grantType string, r *requests.TokenRequest, includeRefreshToken bool) (map[string]interface{}, error) {
	token, err := m.bearerTokenGenerator.Generate(grantType, r.User, r.Client, r.Scopes, includeRefreshToken)
	if err != nil {
		return nil, err
	}

	t := &Token{
		TokenID:      "",
		AccessToken:  "",
		RefreshToken: token.GetRefreshToken(),
		ClientID:     r.Client.GetClientID(),
		TokenType:    token.GetType(),
		Scopes:       token.GetScopes(),
		IssuedAt:     "",
		ExpiresIn:    token.GetExpiresIn(),
		UserID:       r.User.GetSubjectID(),
	}
	if err := m.store.Save(r.Request.Context(), t); err != nil {
		return nil, err
	}

	return token.GetData(), nil
}
