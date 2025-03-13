package rfc6750

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"time"
)

type (
	OpaqueRefreshTokenGenerator struct {
		expiresIn           time.Duration
		expiresInGenerator  ExpiresInGenerator
		randStringGenerator RandStringGenerator
	}

	OpaqueRefreshTokenGeneratorOption func(*OpaqueRefreshTokenGenerator)
)

func NewOpaqueRefreshTokenGenerator(opts ...OpaqueRefreshTokenGeneratorOption) *OpaqueRefreshTokenGenerator {
	g := &OpaqueRefreshTokenGenerator{
		expiresIn: DefaultRefreshTokenExpiresIn,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

func WithRefreshTokenExpiresIn(exp time.Duration) OpaqueRefreshTokenGeneratorOption {
	return func(g *OpaqueRefreshTokenGenerator) {
		g.expiresIn = exp
	}
}

func WithRefreshTokenExpiresInGenerator(fn ExpiresInGenerator) OpaqueRefreshTokenGeneratorOption {
	return func(g *OpaqueRefreshTokenGenerator) {
		g.expiresInGenerator = fn
	}
}

func WithRefreshTokenRandStringGenerator(fn RandStringGenerator) OpaqueRefreshTokenGeneratorOption {
	return func(g *OpaqueRefreshTokenGenerator) {
		g.randStringGenerator = fn
	}
}

func (g *OpaqueRefreshTokenGenerator) Generate(grantType string, token models.Token, user models.User, client models.Client) error {
	expiresIn, err := g.getExpiresIn(grantType, client)
	if err != nil {
		return err
	}
	token.SetRefreshTokenExpiresIn(expiresIn)

	refreshToken, err := g.generate()
	if err != nil {
		return err
	}

	token.SetRefreshToken(refreshToken)
	return nil
}

func (g *OpaqueRefreshTokenGenerator) getExpiresIn(grantType string, client models.Client) (time.Duration, error) {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	if g.expiresIn <= 0 {
		return 0, ErrInvalidExpiresIn
	}

	return g.expiresIn, nil
}

func (g *OpaqueRefreshTokenGenerator) generate() (string, error) {
	if fn := g.randStringGenerator; fn != nil {
		return fn()
	}

	return common.GenerateRandString(RefreshTokenLength, common.SecretCharset)
}
