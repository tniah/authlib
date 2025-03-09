package rfc9068

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"strings"
	"time"
)

var (
	ErrMissingSigningKey    = errors.New("missing signing key")
	ErrMissingSigningMethod = errors.New("missing signing method")
)

type (
	JWTBearerTokenGenerator struct {
		issuer                         string
		signingKey                     []byte
		signingKeyMethod               jwt.SigningMethod
		signingKeyID                   string
		signingKeyGenerator            SigningKeyGenerator
		extraClaimGenerator            ExtraClaimGenerator
		refreshTokenGenerator          TokenGenerator
		accessTokenExpiresInGenerator  ExpiresInGenerator
		refreshTokenExpiresInGenerator ExpiresInGenerator
		refreshTokenLength             int
		accessTokenExpiresIn           time.Duration
		refreshTokenExpiresIn          time.Duration
	}

	TokenGenerator                func(grantType string, user models.User, client models.Client, scopes []string) (string, error)
	SigningKeyGenerator           func(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error)
	ExpiresInGenerator            func(grantType string, client models.Client) (time.Duration, error)
	ExtraClaimGenerator           func(grantType string, user models.User, client models.Client, scopes []string) (map[string]interface{}, error)
	JWTBearerTokenGeneratorOption func(*JWTBearerTokenGenerator)
)

func NewJWTAccessTokenGenerator(issuer string, opts ...JWTBearerTokenGeneratorOption) *JWTBearerTokenGenerator {
	g := &JWTBearerTokenGenerator{
		issuer:                issuer,
		refreshTokenLength:    DefaultRefreshTokenLength,
		accessTokenExpiresIn:  DefaultAccessTokenExpiresIn,
		refreshTokenExpiresIn: DefaultRefreshTokenExpiresIn,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

func WithSigningKey(key []byte) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.signingKey = key
	}
}

func WithSigningKeyMethod(method jwt.SigningMethod) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.signingKeyMethod = method
	}
}

func WithSigningKeyID(keyID string) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.signingKeyID = keyID
	}
}

func WithSigningKeyGenerator(fn SigningKeyGenerator) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.signingKeyGenerator = fn
	}
}

func WithExtraClaimGenerator(fn ExtraClaimGenerator) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.extraClaimGenerator = fn
	}
}

func WithRefreshTokenGenerator(fn TokenGenerator) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.refreshTokenGenerator = fn
	}
}

func WithAccessTokenExpiresInGenerator(fn ExpiresInGenerator) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.accessTokenExpiresInGenerator = fn
	}
}

func WithRefreshTokenExpiresInGenerator(fn ExpiresInGenerator) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.refreshTokenExpiresInGenerator = fn
	}
}

func WithRefreshTokenLength(l int) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.refreshTokenLength = l
	}
}

func WithAccessTokenExpiresIn(exp time.Duration) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.accessTokenExpiresIn = exp
	}
}

func WithRefreshTokenExpiresIn(exp time.Duration) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.refreshTokenExpiresIn = exp
	}
}

func (g *JWTBearerTokenGenerator) Generate(
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
	token.SetJwtID(strings.Replace(uuid.NewString(), "-", "", -1))
	token.SetClientID(client.GetClientID())
	token.SetScopes(allowedScopes)
	token.SetIssuedAt(time.Now())
	token.SetUserID(user.GetSubjectID())

	accessToken, err := g.generateAccessToken(token, grantType, user, client)
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

func (g *JWTBearerTokenGenerator) generateAccessToken(t models.Token, grantType string, user models.User, client models.Client) (string, error) {
	expiresIn, err := g.getAccessTokenExpiresIn(grantType, client)
	if err != nil {
		return "", err
	}

	claims := common.JWTClaim{
		ClaimIssuer:         g.issuer,
		ClaimExpirationTime: jwt.NewNumericDate(t.GetIssuedAt().Add(expiresIn)),
		ClaimAudience:       client.GetClientID(),
		ClaimClientID:       client.GetClientID(),
		ClaimIssuedAt:       jwt.NewNumericDate(t.GetIssuedAt()),
		ClaimScope:          strings.Join(t.GetScopes(), " "),
		ClaimJwtID:          t.GetJwtID(),
	}

	sub := user.GetSubjectID()
	if sub != "" {
		claims[ClaimSubject] = user.GetSubjectID()
	} else {
		claims[ClaimSubject] = client.GetClientID()
	}

	if g.extraClaimGenerator != nil {
		extraClaims, err := g.extraClaimGenerator(grantType, user, client, t.GetScopes())
		if err != nil {
			return "", err
		}

		for k, v := range extraClaims {
			claims[k] = v
		}
	}

	key, method, keyID, err := g.getSigningKey(grantType, client)
	if err != nil {
		return "", err
	}

	token, err := common.NewJWTToken(key, method, keyID)
	if err != nil {
		return "", err
	}
	header := common.JWTHeader{HeaderMediaType: MediaType}
	return token.Generate(claims, header)
}

func (g *JWTBearerTokenGenerator) getSigningKey(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error) {
	if g.signingKeyGenerator != nil {
		signingKey, method, signingKeyID, err := g.signingKeyGenerator(grantType, client)
		if err != nil {
			return nil, nil, "", err
		}

		return signingKey, method, signingKeyID, nil
	}

	if g.signingKey == nil {
		return nil, nil, "", ErrMissingSigningKey
	}

	if g.signingKeyMethod == nil {
		return nil, nil, "", ErrMissingSigningMethod
	}

	return g.signingKey, g.signingKeyMethod, g.signingKeyID, nil
}

func (g *JWTBearerTokenGenerator) generateRefreshToken(grantType string, user models.User, client models.Client, scopes []string) (string, error) {
	if g.refreshTokenGenerator != nil {
		return g.refreshTokenGenerator(grantType, user, client, scopes)
	}

	return common.GenerateRandString(g.refreshTokenLength, common.SecretCharset)
}

func (g *JWTBearerTokenGenerator) getAccessTokenExpiresIn(grantType string, client models.Client) (time.Duration, error) {
	if g.accessTokenExpiresInGenerator != nil {
		return g.accessTokenExpiresInGenerator(grantType, client)
	}

	return g.accessTokenExpiresIn, nil
}

func (g *JWTBearerTokenGenerator) getRefreshTokenExpiresIn(grantType string, client models.Client) (time.Duration, error) {
	if g.refreshTokenExpiresInGenerator != nil {
		return g.refreshTokenExpiresInGenerator(grantType, client)
	}

	return g.refreshTokenExpiresIn, nil
}
