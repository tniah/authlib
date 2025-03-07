package rfc6750

import (
	"github.com/google/uuid"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"strings"
	"time"
)

const (
	DefaultExpiresIn          = time.Minute * 60
	DefaultAccessTokenLength  = 48
	DefaultRefreshTokenLength = 48
	ParamTokenType            = "token_type"
	ParamAccessToken          = "access_token"
	ParamRefreshToken         = "refresh_token"
	ParamExpiresIn            = "expires_in"
	ParamScope                = "scope"
	TokenTypeBearer           = "Bearer"
)

type (
	BearerTokenGenerator struct {
		accessTokenGenerator  TokenGenerator
		refreshTokenGenerator TokenGenerator
		expiresInGenerator    ExpiresInGenerator
		accessTokenLength     int
		refreshTokenLength    int
		expiresIn             time.Duration
	}

	TokenGenerator             func(grantType string, user models.User, client models.Client, scopes []string) (string, error)
	ExpiresInGenerator         func(grantType string, client models.Client) (time.Duration, error)
	BearerTokenGeneratorOption func(*BearerTokenGenerator)
)

func NewBearerTokenGenerator(opts ...BearerTokenGeneratorOption) *BearerTokenGenerator {
	g := &BearerTokenGenerator{
		accessTokenLength:  DefaultAccessTokenLength,
		refreshTokenLength: DefaultRefreshTokenLength,
		expiresIn:          DefaultExpiresIn,
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

func WithExpiresIn(exp time.Duration) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.expiresIn = exp
	}
}

func (g *BearerTokenGenerator) Generate(
	grantType string,
	user models.User,
	client models.Client,
	scopes []string,
	includeRefreshToken bool,
	args ...map[string]interface{},
) (*Token, error) {
	allowedScopes := client.GetAllowedScopes(scopes)
	t := &Token{
		tokenID:  strings.Replace(uuid.NewString(), "-", "", -1),
		clientID: client.GetClientID(),
		scopes:   allowedScopes,
		issuedAt: time.Now(),
		userID:   user.GetSubjectID(),
	}

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

	expiresIn, err := g.getExpiresIn(grantType, client)
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

func (g *BearerTokenGenerator) getExpiresIn(grantType string, client models.Client) (time.Duration, error) {
	if g.expiresInGenerator == nil {
		return g.expiresIn, nil
	}

	return g.expiresInGenerator(grantType, client)
}
