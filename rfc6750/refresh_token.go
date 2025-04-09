package rfc6750

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"time"
)

type OpaqueRefreshTokenGenerator struct {
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	randStringGenerator RandStringGenerator
}

func NewOpaqueRefreshTokenGenerator() *OpaqueRefreshTokenGenerator {
	return &OpaqueRefreshTokenGenerator{
		expiresIn: DefaultRefreshTokenExpiresIn,
	}
}

func (g *OpaqueRefreshTokenGenerator) SetExpiresIn(exp time.Duration) {
	g.expiresIn = exp
}

func (g *OpaqueRefreshTokenGenerator) SetExpiresInGenerator(fn ExpiresInGenerator) {
	g.expiresInGenerator = fn
}

func (g *OpaqueRefreshTokenGenerator) MustExpiresInGenerator(fn ExpiresInGenerator) error {
	if fn == nil {
		return ErrNilExpiresInGenerator
	}

	g.SetExpiresInGenerator(fn)
	return nil
}

func (g *OpaqueRefreshTokenGenerator) SetRandStringGenerator(fn RandStringGenerator) {
	g.randStringGenerator = fn
}

func (g *OpaqueRefreshTokenGenerator) MustRandStringGenerator(fn RandStringGenerator) error {
	if fn == nil {
		return ErrNilRandStringGenerator
	}

	g.SetRandStringGenerator(fn)
	return nil
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
