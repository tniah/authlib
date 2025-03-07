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
		accessTokenGenerator AccessTokenGenerator
		bearerTokenGenerator *rfc6750.BearerTokenGenerator
	}

	TokenStore interface {
		Save(ctx context.Context, token models.Token) error
	}

	AccessTokenGenerator func(grantType string, user models.User, client models.Client, scopes []string, includeRefreshToken bool, args ...map[string]interface{}) (map[string]interface{}, error)
)

func NewTokenManager(store TokenStore, accessTokenGenerator AccessTokenGenerator) *TokenManager {
	return &TokenManager{
		store:                store,
		accessTokenGenerator: accessTokenGenerator,
		bearerTokenGenerator: rfc6750.NewBearerTokenGenerator(),
	}
}

func (m *TokenManager) GenerateAccessToken(grantType string, r *requests.TokenRequest, includeRefreshToken bool) (map[string]interface{}, error) {
	data, err := m.bearerTokenGenerator.Generate(grantType, r.User, r.Client, r.Scopes, includeRefreshToken)
	if err != nil {
		return nil, err
	}

	t := &Token{
		TokenID:      "",
		AccessToken:  "",
		RefreshToken: "",
		ClientID:     r.Client.GetClientID(),
		TokenType:    "",
		Scopes:       []string{},
		IssuedAt:     "",
		ExpiresIn:    "",
		UserID:       "",
	}
	if err := m.store.Save(r.Request.Context(), t); err != nil {
		return nil, err
	}

	return data, nil
}
