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
		issuer                string
		signingKey            []byte
		signingKeyMethod      jwt.SigningMethod
		signingKeyID          string
		signingKeyGenerator   SigningKeyGenerator
		extraClaimGenerator   ExtraClaimGenerator
		refreshTokenGenerator TokenGenerator
		expiresInGenerator    ExpiresInGenerator
		refreshTokenLength    int
		expiresIn             time.Duration
	}

	TokenGenerator                func(grantType string, user models.User, client models.Client, scopes []string) (string, error)
	SigningKeyGenerator           func(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error)
	ExpiresInGenerator            func(grantType string, client models.Client) (time.Duration, error)
	ExtraClaimGenerator           func(grantType string, user models.User, client models.Client, scopes []string) (map[string]interface{}, error)
	JWTBearerTokenGeneratorOption func(*JWTBearerTokenGenerator)
)

func NewJWTAccessTokenGenerator(issuer string, opts ...JWTBearerTokenGeneratorOption) *JWTBearerTokenGenerator {
	g := &JWTBearerTokenGenerator{
		issuer:             issuer,
		refreshTokenLength: DefaultRefreshTokenLength,
		expiresIn:          DefaultExpiresIn,
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

func WithExpiresInGenerator(fn ExpiresInGenerator) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.expiresInGenerator = fn
	}
}

func WithRefreshTokenLength(l int) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.refreshTokenLength = l
	}
}

func WithExpiresIn(exp time.Duration) JWTBearerTokenGeneratorOption {
	return func(g *JWTBearerTokenGenerator) {
		g.expiresIn = exp
	}
}

func (g *JWTBearerTokenGenerator) Generate(
	grantType string,
	user models.User,
	client models.Client,
	scopes []string,
	includeRefreshToken bool,
	args ...map[string]interface{},
) (models.Token, error) {
	allowedScopes := client.GetAllowedScopes(scopes)
	t := &Token{
		tokenID:  strings.Replace(uuid.NewString(), "-", "", -1),
		clientID: client.GetClientID(),
		scopes:   allowedScopes,
		issuedAt: time.Now(),
		userID:   user.GetSubjectID(),
	}

	accessToken, err := g.generateAccessToken(t, grantType, user, client)
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

func (g *JWTBearerTokenGenerator) generateAccessToken(t *Token, grantType string, user models.User, client models.Client) (string, error) {
	expiresIn, err := g.getExpiresIn(grantType, client)
	if err != nil {
		return "", err
	}

	claims := common.JWTClaim{
		ClaimIssuer:         g.issuer,
		ClaimExpirationTime: jwt.NewNumericDate(t.issuedAt.Add(expiresIn)),
		ClaimAudience:       client.GetClientID(),
		ClaimClientID:       client.GetClientID(),
		ClaimIssuedAt:       jwt.NewNumericDate(t.issuedAt),
		ClaimScope:          strings.Join(t.scopes, " "),
		ClaimJwtID:          t.tokenID,
	}

	sub := user.GetSubjectID()
	if sub != "" {
		claims[ClaimSubject] = user.GetSubjectID()
	} else {
		claims[ClaimSubject] = client.GetClientID()
	}

	if g.extraClaimGenerator != nil {
		extraClaims, err := g.extraClaimGenerator(grantType, user, client, t.scopes)
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

func (g *JWTBearerTokenGenerator) getExpiresIn(grantType string, client models.Client) (time.Duration, error) {
	if g.expiresInGenerator != nil {
		return g.expiresInGenerator(grantType, client)
	}

	return g.expiresIn, nil
}
