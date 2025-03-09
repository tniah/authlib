package rfc6750

import (
	"github.com/google/uuid"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"strings"
	"time"
)

const (
	TokenTypeBearer              = "Bearer"
	DefaultAccessTokenExpiresIn  = time.Minute * 60
	DefaultRefreshTokenExpiresIn = time.Minute * 60 * 24
	DefaultAccessTokenLength     = 48
	DefaultRefreshTokenLength    = 48
)

type (
	BearerTokenGenerator struct {
		accessTokenGenerator           TokenGenerator
		refreshTokenGenerator          TokenGenerator
		accessTokenExpiresInGenerator  ExpiresInGenerator
		refreshTokenExpiresInGenerator ExpiresInGenerator
		accessTokenLength              int
		refreshTokenLength             int
		accessTokenExpiresIn           time.Duration
		refreshTokenExpiresIn          time.Duration
	}

	TokenGenerator             func(grantType string, user models.User, client models.Client, scopes []string) (string, error)
	ExpiresInGenerator         func(grantType string, client models.Client) (time.Duration, error)
	BearerTokenGeneratorOption func(*BearerTokenGenerator)
)

func NewBearerTokenGenerator(opts ...BearerTokenGeneratorOption) *BearerTokenGenerator {
	g := &BearerTokenGenerator{
		accessTokenLength:     DefaultAccessTokenLength,
		refreshTokenLength:    DefaultRefreshTokenLength,
		accessTokenExpiresIn:  DefaultAccessTokenExpiresIn,
		refreshTokenExpiresIn: DefaultRefreshTokenExpiresIn,
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
		g.accessTokenExpiresInGenerator = fn
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

func WithRefreshTokenExpiresIn(exp time.Duration) BearerTokenGeneratorOption {
	return func(g *BearerTokenGenerator) {
		g.refreshTokenExpiresIn = exp
	}
}

func (g *BearerTokenGenerator) Generate(
	token models.Token,
	grantType string,
	user models.User,
	client models.Client,
	scopes []string,
	includeRefreshToken bool,
	args ...map[string]interface{},
) error {
	allowedScopes := client.GetAllowedScopes(scopes)
	token.SetType(TokenTypeBearer)
	token.SetID(strings.Replace(uuid.NewString(), "-", "", -1))
	token.SetClientID(client.GetClientID())
	token.SetScopes(allowedScopes)
	token.SetIssuedAt(time.Now())
	token.SetUserID(user.GetSubjectID())

	accessToken, err := g.generateAccessToken(grantType, user, client, allowedScopes)
	if err != nil {
		return err
	}
	token.SetAccessToken(accessToken)

	atExpiresIn, err := g.getAccessTokenExpiresIn(grantType, client)
	if err != nil {
		return err
	}
	token.SetAccessTokenExpiresIn(atExpiresIn)

	if includeRefreshToken {
		refreshToken, err := g.generateRefreshToken(grantType, user, client, allowedScopes)
		if err != nil {
			return err
		}
		token.SetRefreshToken(refreshToken)

		rtExpiresIn, err := g.getRefreshTokenExpiresIn(grantType, client)
		if err != nil {
			return err
		}
		token.SetRefreshTokenExpiresIn(rtExpiresIn)
	}

	if len(args) > 0 {
		token.SetExtraData(args[0])
	}

	return nil
}

func (g *BearerTokenGenerator) generateAccessToken(grantType string, user models.User, client models.Client, scopes []string) (string, error) {
	if g.accessTokenGenerator != nil {
		return g.accessTokenGenerator(grantType, user, client, scopes)
	}

	return common.GenerateRandString(g.accessTokenLength, common.SecretCharset)
}

func (g *BearerTokenGenerator) generateRefreshToken(grantType string, user models.User, client models.Client, scopes []string) (string, error) {
	if g.refreshTokenGenerator != nil {
		return g.refreshTokenGenerator(grantType, user, client, scopes)
	}

	return common.GenerateRandString(g.refreshTokenLength, common.SecretCharset)
}

func (g *BearerTokenGenerator) getAccessTokenExpiresIn(grantType string, client models.Client) (time.Duration, error) {
	if g.accessTokenExpiresInGenerator != nil {
		return g.accessTokenExpiresInGenerator(grantType, client)
	}

	return g.accessTokenExpiresIn, nil
}

func (g *BearerTokenGenerator) getRefreshTokenExpiresIn(grantType string, client models.Client) (time.Duration, error) {
	if g.refreshTokenExpiresInGenerator != nil {
		return g.refreshTokenExpiresInGenerator(grantType, client)
	}

	return g.refreshTokenExpiresIn, nil
}
