package rfc6750

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"time"
)

const (
	DefaultAccessTokenExpiresIn = time.Minute * 60
	DefaultAccessTokenLength    = 48
	DefaultRefreshTokenLength   = 48
	ParamAccessToken            = "access_token"
	ParamTokenType              = "token_type"
	ParamExpiresIn              = "expires_in"
	ParamRefreshToken           = "refresh_token"
	TokenTypeBearer             = "Bearer"
)

type (
	BearerTokenGenerator struct {
		accessTokenGenerator  TokenGenerator
		refreshTokenGenerator TokenGenerator
		expiresInGenerator    ExpiresInGenerator
		accessTokenLength     int
		refreshTokenLength    int
		accessTokenExpiresIn  time.Duration
	}

	TokenGenerator             func(grantType string, user models.User, client models.Client, scopes []string) (string, error)
	ExpiresInGenerator         func(grantType string, client models.Client) (time.Duration, error)
	BearerTokenGeneratorOption func(*BearerTokenGenerator)
)

func NewBearerTokenGenerator(opts ...BearerTokenGeneratorOption) *BearerTokenGenerator {
	g := &BearerTokenGenerator{
		accessTokenLength:    DefaultAccessTokenLength,
		refreshTokenLength:   DefaultRefreshTokenLength,
		accessTokenExpiresIn: DefaultAccessTokenExpiresIn,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

func WithAccessTokenGenerator(fn TokenGenerator) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.accessTokenGenerator = fn
	}
}

func WithRefreshTokenGenerator(fn TokenGenerator) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.refreshTokenGenerator = fn
	}
}

func WithExpiresInGenerator(fn ExpiresInGenerator) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.expiresInGenerator = fn
	}
}

func WithAccessTokenLength(l int) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.accessTokenLength = l
	}
}

func WithRefreshTokenLength(l int) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.refreshTokenLength = l
	}
}

func WithAccessTokenExpiresIn(exp time.Duration) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.accessTokenExpiresIn = exp
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
	if g.accessTokenGenerator == nil {
		return common.GenerateRandString(g.accessTokenLength, common.SecretCharset)
	}

	return g.accessTokenGenerator(grantType, user, client, scopes)
}

func (g *BearerTokenGenerator) generateRefreshToken(grantType string, user models.User, client models.Client, scopes []string) (string, error) {
	if g.refreshTokenGenerator == nil {
		return common.GenerateRandString(g.refreshTokenLength, common.SecretCharset)
	}

	return g.refreshTokenGenerator(grantType, user, client, scopes)
}

func (g *BearerTokenGenerator) expiresIn(grantType string, client models.Client) (time.Duration, error) {
	if g.expiresInGenerator == nil {
		return g.accessTokenExpiresIn, nil
	}

	return g.expiresInGenerator(grantType, client)
}
