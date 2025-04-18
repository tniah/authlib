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
	expiresIn := g.expiresInHandler(r.GrantType.String(), r.Client)
	token.SetRefreshTokenExpiresIn(expiresIn)

	refreshToken := g.genToken(r.GrantType.String(), r.Client)
	token.SetRefreshToken(refreshToken)
	return nil
}

func (g *OpaqueRefreshTokenGenerator) expiresInHandler(grantType string, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.expiresIn
}

func (g *OpaqueRefreshTokenGenerator) genToken(gt string, c models.Client) string {
	if fn := g.randStringGenerator; fn != nil {
		return fn(gt, c)
	}

	randStr, _ := common.GenerateRandString(g.tokenLength, common.SecretCharset)
	return randStr
}
