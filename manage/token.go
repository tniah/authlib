package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/rfc6750"
	"sync"
)

var ErrNilPointerToken = errors.New("token is a nil pointer")

type (
	TokenManager struct {
		lock                        *sync.Mutex
		store                       TokenStore
		accessTokenGenerator        AccessTokenGenerator
		defaultAccessTokenGenerator AccessTokenGenerator
	}

	TokenManagerOption func(m *TokenManager)

	TokenStore interface {
		New(ctx context.Context) models.Token
		Save(ctx context.Context, token models.Token) error
	}

	AccessTokenGenerator interface {
		Generate(
			token models.Token,
			grantType string,
			user models.User,
			client models.Client,
			scopes []string,
			includeRefreshToken bool,
			args ...map[string]interface{},
		) error
	}
)

func NewTokenManager(store TokenStore, opts ...TokenManagerOption) *TokenManager {
	m := &TokenManager{store: store, lock: &sync.Mutex{}}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

func WithAccessTokenGenerator(g AccessTokenGenerator) TokenManagerOption {
	return func(m *TokenManager) {
		m.accessTokenGenerator = g
	}
}

func (m *TokenManager) GenerateAccessToken(grantType string, r *requests.TokenRequest, includeRefreshToken bool) (models.Token, error) {
	generator := m.accessTokenGenerator
	if generator == nil {
		generator = m.getDefaultAccessTokenGenerator()
	}

	token, err := m.newToken(r.Request.Context())
	if err != nil {
		return nil, err
	}

	err = generator.Generate(token, grantType, r.User, r.Client, r.Scopes, includeRefreshToken)
	if err != nil {
		return nil, err
	}

	if err := m.store.Save(r.Request.Context(), token); err != nil {
		return nil, err
	}

	return token, nil
}

func (m *TokenManager) newToken(ctx context.Context) (models.Token, error) {
	t := m.store.New(ctx)
	if t == nil {
		return nil, ErrNilPointerToken
	}

	return t, nil
}

func (m *TokenManager) getDefaultAccessTokenGenerator() AccessTokenGenerator {
	if m.defaultAccessTokenGenerator == nil {
		m.lock.Lock()
		defer m.lock.Unlock()

		if m.defaultAccessTokenGenerator == nil {
			m.defaultAccessTokenGenerator = rfc6750.NewBearerTokenGenerator()
		}
	}

	return m.defaultAccessTokenGenerator
}
