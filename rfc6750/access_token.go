package rfc6750

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"time"
)

type (
	OpaqueAccessTokenGenerator struct {
		expiresIn           time.Duration
		expiresInGenerator  ExpiresInGenerator
		randStringGenerator RandStringGenerator
	}

	OpaqueAccessTokenGeneratorOption func(*OpaqueAccessTokenGenerator)
)

func NewOpaqueAccessTokenGenerator(opts ...OpaqueAccessTokenGeneratorOption) *OpaqueAccessTokenGenerator {
	g := &OpaqueAccessTokenGenerator{
		expiresIn: DefaultAccessTokenExpiresIn,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

func WithAccessTokenExpiresIn(exp time.Duration) OpaqueAccessTokenGeneratorOption {
	return func(g *OpaqueAccessTokenGenerator) {
		g.expiresIn = exp
	}
}

func WithAccessTokenExpiresInGenerator(fn ExpiresInGenerator) OpaqueAccessTokenGeneratorOption {
	return func(g *OpaqueAccessTokenGenerator) {
		g.expiresInGenerator = fn
	}
}

func WithAccessTokenRandStringGenerator(fn RandStringGenerator) OpaqueAccessTokenGeneratorOption {
	return func(g *OpaqueAccessTokenGenerator) {
		g.randStringGenerator = fn
	}
}

func (g *OpaqueAccessTokenGenerator) Generate(grantType string, token models.Token, user models.User, client models.Client, scopes []string) error {
	token.SetClientID(client.GetClientID())
	token.SetUserID(user.GetSubjectID())

	allowedScopes := client.GetAllowedScopes(scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now()
	token.SetIssuedAt(issuedAt)

	expiresIn, err := g.getExpiresIn(grantType, client)
	if err != nil {
		return err
	}
	token.SetAccessTokenExpiresIn(expiresIn)

	opaqueToken, err := g.generate()
	if err != nil {
		return err
	}

	token.SetAccessToken(opaqueToken)
	return nil
}

func (g *OpaqueAccessTokenGenerator) getExpiresIn(grantType string, client models.Client) (time.Duration, error) {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	if g.expiresIn <= 0 {
		return 0, ErrInvalidExpiresIn
	}

	return g.expiresIn, nil
}

func (g *OpaqueAccessTokenGenerator) generate() (string, error) {
	if fn := g.randStringGenerator; fn != nil {
		return fn()
	}

	return common.GenerateRandString(AccessTokenLength, common.SecretCharset)
}
