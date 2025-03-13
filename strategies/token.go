package strategies

import (
	"context"
	"errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/rfc6750"
)

var ErrNilPointerToken = errors.New("token is a nil pointer")

type (
	TokenStrategy struct {
		store     TokenStore
		generator Generator
	}

	TokenStore interface {
		New(ctx context.Context) models.Token
		Save(ctx context.Context, token models.Token) error
	}

	Generator interface {
		Generate(
			grantType string,
			token models.Token,
			user models.User,
			client models.Client,
			scopes []string,
			includeRefreshToken bool,
		) error
	}

	TokenStrategyOption func(m *TokenStrategy)
)

func NewTokenGenerator(store TokenStore, opts ...TokenStrategyOption) *TokenStrategy {
	m := &TokenStrategy{
		store:     store,
		generator: rfc6750.NewBearerTokenGenerator(),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

func WithAccessTokenGenerator(g Generator) TokenStrategyOption {
	return func(m *TokenStrategy) {
		m.generator = g
	}
}

func (m *TokenStrategy) GenerateAccessToken(grantType string, r *requests.TokenRequest, includeRefreshToken bool) (models.Token, error) {
	token := m.store.New(r.Request.Context())
	if token == nil {
		return nil, ErrNilPointerToken
	}

	err := m.generator.Generate(grantType, token, r.User, r.Client, r.Scopes, includeRefreshToken)
	if err != nil {
		return nil, err
	}

	if err := m.store.Save(r.Request.Context(), token); err != nil {
		return nil, err
	}

	return token, nil
}
