package rfc6750

import (
	"context"
	"time"

	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/utils"
)

const DefaultRefreshTokenExpiresIn = time.Hour * 24

// OpaqueRefreshTokenGenerator generates a random opaque refresh token.
// Default expiry is 24 hours (DefaultRefreshTokenExpiresIn).
type OpaqueRefreshTokenGenerator struct {
	*TokenGeneratorOptions
}

// NewOpaqueRefreshTokenGenerator creates a generator with optional custom options.
func NewOpaqueRefreshTokenGenerator(opts ...*TokenGeneratorOptions) *OpaqueRefreshTokenGenerator {
	if len(opts) > 0 {
		return &OpaqueRefreshTokenGenerator{TokenGeneratorOptions: opts[0]}
	}

	defaultOpts := NewTokenGeneratorOptions().SetExpiresIn(DefaultRefreshTokenExpiresIn)
	return &OpaqueRefreshTokenGenerator{defaultOpts}
}

// Generate populates token with a refresh token and its expiry duration.
func (g *OpaqueRefreshTokenGenerator) Generate(token models.Token, r *requests.TokenRequest) error {
	// Prefer request context for custom generators; fall back to Background.
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
