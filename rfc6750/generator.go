package rfc6750

import (
	"errors"
	"github.com/tniah/authlib/models"
)

var (
	ErrNilAccessTokenGenerator  = errors.New("access token generator is nil")
	ErrNilRefreshTokenGenerator = errors.New("refresh token generator is nil")
)

type BearerTokenGenerator struct {
	atGenerator TokenGenerator
	rtGenerator TokenGenerator
}

func NewBearerTokenGenerator() *BearerTokenGenerator {
	return &BearerTokenGenerator{
		atGenerator: NewOpaqueAccessTokenGenerator(),
		rtGenerator: NewOpaqueRefreshTokenGenerator(),
	}
}

func (g *BearerTokenGenerator) SetAccessTokenGenerator(fn TokenGenerator) {
	g.atGenerator = fn
}

func (g *BearerTokenGenerator) MustAccessTokenGenerator(fn TokenGenerator) error {
	if fn == nil {
		return ErrNilAccessTokenGenerator
	}

	g.SetAccessTokenGenerator(fn)
	return nil
}

func (g *BearerTokenGenerator) SetRefreshTokenGenerator(fn TokenGenerator) {
	g.rtGenerator = fn
}

func (g *BearerTokenGenerator) MustRefreshTokenGenerator(fn TokenGenerator) error {
	if fn == nil {
		return ErrNilRefreshTokenGenerator
	}

	g.SetRefreshTokenGenerator(fn)
	return nil
}

func (g *BearerTokenGenerator) Generate(
	grantType string,
	token models.Token,
	client models.Client,
	user models.User,
	scopes []string,
	includeRefreshToken bool,
) error {
	if err := g.atGenerator.Generate(grantType, token, client, user, scopes); err != nil {
		return err
	}

	if includeRefreshToken {
		if err := g.rtGenerator.Generate(grantType, token, client, user, scopes); err != nil {
			return err
		}
	}

	token.SetType(TokenTypeBearer)
	return nil
}
