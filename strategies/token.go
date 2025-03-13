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
		generator TokenGenerator
	}

	TokenStore interface {
		New(ctx context.Context) models.Token
		Save(ctx context.Context, token models.Token) error
	}

	TokenGenerator interface {
		Generate(
			grantType string,
			token models.Token,
			user models.User,
			client models.Client,
			scopes []string,
			includeRefreshToken bool,
		) error
	}

	TokenStrategyOption func(s *TokenStrategy)
)

func NewTokenStrategy(store TokenStore, opts ...TokenStrategyOption) *TokenStrategy {
	m := &TokenStrategy{
		store:     store,
		generator: rfc6750.NewBearerTokenGenerator(),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

func WithTokenGenerator(g TokenGenerator) TokenStrategyOption {
	return func(s *TokenStrategy) {
		s.generator = g
	}
}

func (s *TokenStrategy) Generate(grantType string, r *requests.TokenRequest, includeRefreshToken bool) (models.Token, error) {
	token := s.store.New(r.Request.Context())
	if token == nil {
		return nil, ErrNilPointerToken
	}

	err := s.generator.Generate(grantType, token, r.User, r.Client, r.Scopes, includeRefreshToken)
	if err != nil {
		return nil, err
	}

	if err = s.store.Save(r.Request.Context(), token); err != nil {
		return nil, err
	}

	return token, nil
}
