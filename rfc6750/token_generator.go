package rfc6750

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"time"
)

const (
	DefaultExpiresIn          = time.Minute * 60
	DefaultAccessTokenLength  = 48
	DefaultRefreshTokenLength = 48
	ParamAccessToken          = "access_token"
	ParamTokenType            = "token_type"
	ParamExpiresIn            = "expires_in"
	ParamRefreshToken         = "refresh_token"
	TokenTypeBearer           = "Bearer"
)

type (
	BearerTokenGenerator struct {
		AccessTokenGenerator  TokenGenerator
		RefreshTokenGenerator TokenGenerator
		ExpiresInGenerator    ExpiresInGenerator
	}

	TokenGenerator             func(grantType string, user models.User, client models.Client, scopes []string) (string, error)
	ExpiresInGenerator         func(grantType string, client models.Client) (time.Duration, error)
	BearerTokenGeneratorOption func(*BearerTokenGenerator)
)

func NewBearerTokenGenerator(opts ...BearerTokenGeneratorOption) *BearerTokenGenerator {
	g := &BearerTokenGenerator{}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

func WithAccessTokenGenerator(fn TokenGenerator) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.AccessTokenGenerator = fn
	}
}

func WithRefreshTokenGenerator(fn TokenGenerator) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.RefreshTokenGenerator = fn
	}
}

func WithExpiresInGenerator(fn ExpiresInGenerator) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.ExpiresInGenerator = fn
	}
}

func (g *BearerTokenGenerator) Generate(
	grantType string,
	user models.User,
	client models.Client,
	scopes []string,
	includeRefreshToken bool,
	args ...map[string]interface{},
) (Token, error) {
	allowedScopes := client.GetAllowedScopes(scopes)
	t := &token{scopes: allowedScopes}

	accessToken, err := g.generateAccessToken(grantType, user, client, allowedScopes)
	if err != nil {
		return nil, err
	}
	t.accessToken = accessToken

	if includeRefreshToken {
		refreshToken, err := g.generateRefreshToken(grantType, user, client, allowedScopes)
		if err != nil {
			return nil, err
		}
		t.refreshToken = refreshToken
	}

	expiresIn, err := g.expiresIn(grantType, client)
	if err != nil {
		return nil, err
	}
	t.expiresIn = expiresIn

	if len(args) > 0 {
		t.extraData = args[0]
	}

	return t, nil
}

func (g *BearerTokenGenerator) generateAccessToken(grantType string, user models.User, client models.Client, scopes []string) (string, error) {
	if g.AccessTokenGenerator == nil {
		return common.GenerateRandString(DefaultAccessTokenLength, common.SecretCharset)
	}

	return g.AccessTokenGenerator(grantType, user, client, scopes)
}

func (g *BearerTokenGenerator) generateRefreshToken(grantType string, user models.User, client models.Client, scopes []string) (string, error) {
	if g.RefreshTokenGenerator == nil {
		return common.GenerateRandString(DefaultRefreshTokenLength, common.SecretCharset)
	}

	return g.RefreshTokenGenerator(grantType, user, client, scopes)
}

func (g *BearerTokenGenerator) expiresIn(grantType string, client models.Client) (time.Duration, error) {
	if g.ExpiresInGenerator == nil {
		return DefaultExpiresIn, nil
	}

	return g.ExpiresInGenerator(grantType, client)
}
