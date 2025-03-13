package rfc6750

import (
	"github.com/tniah/authlib/models"
)

type (
	BearerTokenGenerator struct {
		accessTokenGenerator  AccessTokenGenerator
		refreshTokenGenerator RefreshTokenGenerator
	}

	BearerTokenGeneratorOption func(*BearerTokenGenerator)
)

func NewBearerTokenGenerator(opts ...BearerTokenGeneratorOption) *BearerTokenGenerator {
	g := &BearerTokenGenerator{
		accessTokenGenerator:  NewOpaqueAccessTokenGenerator(),
		refreshTokenGenerator: NewOpaqueRefreshTokenGenerator(),
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

func WithAccessTokenGenerator(generator AccessTokenGenerator) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.accessTokenGenerator = generator
	}
}

func WithRefreshTokenGenerator(generator RefreshTokenGenerator) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.refreshTokenGenerator = generator
	}
}

func (g *BearerTokenGenerator) Generate(
	grantType string,
	token models.Token,
	user models.User,
	client models.Client,
	scopes []string,
	includeRefreshToken bool,
) error {
	if err := g.accessTokenGenerator.Generate(grantType, token, user, client, scopes); err != nil {
		return err
	}

	if includeRefreshToken {
		if err := g.refreshTokenGenerator.Generate(grantType, token, user, client); err != nil {
			return err
		}
	}

	token.SetType(TokenTypeBearer)
	return nil
}
