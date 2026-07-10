package rfc6750

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/utils"
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
	ctx := context.Background()
	if r.Request != nil {
		ctx = r.Request.Context()
	}

	expiresIn := g.expiresInHandler(ctx, r.GrantType.String(), r.Client)
	token.SetRefreshTokenExpiresIn(expiresIn)

	refreshToken := g.genToken(ctx, r.GrantType.String(), r.Client)
	token.SetRefreshToken(refreshToken)
	return nil
}

func (g *OpaqueRefreshTokenGenerator) expiresInHandler(ctx context.Context, grantType string, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	return g.expiresIn
}

func (g *OpaqueRefreshTokenGenerator) genToken(ctx context.Context, gt string, c models.Client) string {
	if fn := g.randStringGenerator; fn != nil {
		return fn(ctx, gt, c)
	}

	randStr, _ := utils.GenerateRandString(g.tokenLength, utils.SecretCharset)
	return randStr
}
