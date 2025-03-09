package strategies

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
	TokenGenerator struct {
		lock                        *sync.Mutex
		newToken                    NewToken
		saveToken                   SaveToken
		accessTokenGenerator        AccessTokenGenerator
		defaultAccessTokenGenerator AccessTokenGenerator
	}
	NewToken             func(ctx context.Context) models.Token
	SaveToken            func(ctx context.Context, token models.Token) error
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
	TokenGeneratorOption func(m *TokenGenerator)
)

func NewTokenGenerator(newToken NewToken, saveToken SaveToken, opts ...TokenGeneratorOption) *TokenGenerator {
	m := &TokenGenerator{
		newToken:  newToken,
		saveToken: saveToken,
		lock:      &sync.Mutex{},
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

func WithAccessTokenGenerator(g AccessTokenGenerator) TokenGeneratorOption {
	return func(m *TokenGenerator) {
		m.accessTokenGenerator = g
	}
}

func (m *TokenGenerator) GenerateAccessToken(grantType string, r *requests.TokenRequest, includeRefreshToken bool) (models.Token, error) {
	generator := m.accessTokenGenerator
	if generator == nil {
		generator = m.getDefaultAccessTokenGenerator()
	}

	token := m.newToken(r.Request.Context())
	if token != nil {
		return nil, ErrNilPointerToken
	}

	err := generator.Generate(token, grantType, r.User, r.Client, r.Scopes, includeRefreshToken)
	if err != nil {
		return nil, err
	}

	if err := m.saveToken(r.Request.Context(), token); err != nil {
		return nil, err
	}

	return token, nil
}

func (m *TokenGenerator) getDefaultAccessTokenGenerator() AccessTokenGenerator {
	if m.defaultAccessTokenGenerator == nil {
		m.lock.Lock()
		defer m.lock.Unlock()

		if m.defaultAccessTokenGenerator == nil {
			m.defaultAccessTokenGenerator = rfc6750.NewBearerTokenGenerator()
		}
	}

	return m.defaultAccessTokenGenerator
}
