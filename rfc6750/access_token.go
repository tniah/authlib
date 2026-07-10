package rfc6750

import (
	"context"
	"errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/utils"
	"time"
)

var ErrNilClient = errors.New("client is nil")

type OpaqueAccessTokenGenerator struct {
	*TokenGeneratorOptions
}

func NewOpaqueAccessTokenGenerator(opts ...*TokenGeneratorOptions) *OpaqueAccessTokenGenerator {
	if len(opts) > 0 {
		return &OpaqueAccessTokenGenerator{opts[0]}
	}

	defaultOpts := NewTokenGeneratorOptions()
	return &OpaqueAccessTokenGenerator{defaultOpts}
}

func (g *OpaqueAccessTokenGenerator) Generate(token models.Token, r *requests.TokenRequest) error {
	client := r.Client
	if client == nil {
		return ErrNilClient
	}

	ctx := context.Background()
	if r.Request != nil {
		ctx = r.Request.Context()
	}

	token.SetClientID(client.GetClientID())

	if user := r.User; user != nil {
		token.SetUserID(user.GetUserID())
	}

	allowedScopes := client.GetAllowedScopes(r.Scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now().UTC().Round(time.Second)
	token.SetIssuedAt(issuedAt)

	expiresIn := g.expiresInHandler(ctx, r.GrantType.String(), client)
	token.SetAccessTokenExpiresIn(expiresIn)

	opaqueToken := g.genToken(ctx, r.GrantType.String(), client)
	token.SetAccessToken(opaqueToken)
	return nil
}

func (g *OpaqueAccessTokenGenerator) expiresInHandler(ctx context.Context, grantType string, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	return g.expiresIn
}

func (g *OpaqueAccessTokenGenerator) genToken(ctx context.Context, grantType string, c models.Client) string {
	if fn := g.randStringGenerator; fn != nil {
		return fn(ctx, grantType, c)
	}

	randStr, _ := utils.GenerateRandString(g.tokenLength, utils.SecretCharset)
	return randStr
}
