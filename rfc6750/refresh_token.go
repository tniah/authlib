package rfc6750

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"time"
)

const DefaultRefreshTokenExpiresIn = time.Hour * 24

type OpaqueRefreshTokenGenerator struct {
	*TokenGeneratorOptions
}

func NewOpaqueRefreshTokenGenerator(opts ...*TokenGeneratorOptions) *OpaqueRefreshTokenGenerator {
	if len(opts) > 0 {
		return &OpaqueRefreshTokenGenerator{TokenGeneratorOptions: opts[0]}
	}

	defaultOpts := NewTokenGeneratorOptions().SetExpiresIn(DefaultRefreshTokenExpiresIn)
	return &OpaqueRefreshTokenGenerator{defaultOpts}
}

func (g *OpaqueRefreshTokenGenerator) Generate(token models.Token, r *requests.TokenRequest) error {
	expiresIn, err := g.expiresInHandler(r.GrantType, r.Client)
	if err != nil {
		return err
	}
	token.SetRefreshTokenExpiresIn(expiresIn)

	refreshToken, err := g.genToken(r.GrantType, r.Client)
	if err != nil {
		return err
	}

	token.SetRefreshToken(refreshToken)
	return nil
}

func (g *OpaqueRefreshTokenGenerator) expiresInHandler(grantType string, client models.Client) (time.Duration, error) {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.expiresIn, nil
}

func (g *OpaqueRefreshTokenGenerator) genToken(gt string, c models.Client) (string, error) {
	if fn := g.randStringGenerator; fn != nil {
		return fn(gt, c)
	}

	return common.GenerateRandString(g.tokenLength, common.SecretCharset)
}
