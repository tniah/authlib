package rfc6750

import (
	"github.com/tniah/authlib/models"
)

type BearerTokenGenerator struct {
	atGenerator AccessTokenGenerator
	rtGenerator RefreshTokenGenerator
}

func NewBearerTokenGenerator() *BearerTokenGenerator {
	return &BearerTokenGenerator{
		atGenerator: NewOpaqueAccessTokenGenerator(),
		rtGenerator: NewOpaqueRefreshTokenGenerator(),
	}
}

func (g *BearerTokenGenerator) SetAccessTokenGenerator(fn AccessTokenGenerator) {
	g.atGenerator = fn
}

func (g *BearerTokenGenerator) MustAccessTokenGenerator(fn AccessTokenGenerator) error {
	if fn == nil {
		return ErrNilAccessTokenGenerator
	}

	g.SetAccessTokenGenerator(fn)
	return nil
}

func (g *BearerTokenGenerator) SetRefreshTokenGenerator(fn RefreshTokenGenerator) {
	g.rtGenerator = fn
}

func (g *BearerTokenGenerator) MustRefreshTokenGenerator(fn RefreshTokenGenerator) error {
	if fn == nil {
		return ErrNilRefreshTokenGenerator
	}

	g.SetRefreshTokenGenerator(fn)
	return nil
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
