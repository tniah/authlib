package rfc9068

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"strings"
	"time"
)

const (
	DefaultExpiresIn    = time.Minute * 60
	DefaultJwtIDLength  = 32
	ClaimIssuer         = "iss"
	ClaimSubject        = "sub"
	ClaimAudience       = "aud"
	ClaimExpirationTime = "exp"
	ClaimIssuedAt       = "iat"
	ClaimJwtID          = "jti"
	ClaimScope          = "scope"
	ClaimClientID       = "client_id"
	HeaderMediaType     = "typ"
	MediaType           = "at+JWT"
)

var (
	ErrMissingSigningKey    = errors.New("missing signing key")
	ErrMissingSigningMethod = errors.New("missing signing method")
)

type (
	JWTAccessTokenGenerator struct {
		Issuer              string
		ExpiresInGenerator  ExpiresInGenerator
		SigningKeyGenerator SigningKeyGenerator
		SigningKey          []byte
		SigningKeyMethod    jwt.SigningMethod
		SigningKeyID        string
		ExtraClaimGenerator ExtraClaimGenerator
	}

	SigningKeyGenerator func(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error)
	ExpiresInGenerator  func(grantType string, client models.Client) (time.Duration, error)
	ExtraClaimGenerator func(grantType string, user models.User, client models.Client, scopes []string) (map[string]interface{}, error)
)

func NewJWTAccessTokenGenerator(issuer string) *JWTAccessTokenGenerator {
	return &JWTAccessTokenGenerator{Issuer: issuer}
}

func (g *JWTAccessTokenGenerator) Generate(grantType string, user models.User, client models.Client, scopes []string) (string, error) {
	now := time.Now()
	expiresIn, err := g.expiresIn(grantType, client)
	if err != nil {
		return "", err
	}

	claims := common.JWTClaim{
		ClaimIssuer:         g.Issuer,
		ClaimExpirationTime: jwt.NewNumericDate(now.Add(expiresIn)),
		ClaimAudience:       client.GetClientID(),
		ClaimClientID:       client.GetClientID(),
		ClaimIssuedAt:       jwt.NewNumericDate(now),
		ClaimScope:          strings.Join(scopes, " "),
	}

	sub := user.GetSubjectID()
	if sub != "" {
		claims[ClaimSubject] = user.GetSubjectID()
	} else {
		claims[ClaimSubject] = client.GetClientID()
	}

	jwtID, err := g.jwtID()
	if err != nil {
		return "", err
	}
	claims[ClaimJwtID] = jwtID

	if g.ExtraClaimGenerator != nil {
		extraClaims, err := g.ExtraClaimGenerator(grantType, user, client, scopes)
		if err != nil {
			return "", err
		}

		for k, v := range extraClaims {
			claims[k] = v
		}
	}

	key, method, keyID, err := g.SigningKeyGenerator(grantType, client)
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

func (g *JWTAccessTokenGenerator) expiresIn(grantType string, client models.Client) (time.Duration, error) {
	if g.ExpiresInGenerator == nil {
		return DefaultExpiresIn, nil
	}

	return g.ExpiresInGenerator(grantType, client)
}

func (g *JWTAccessTokenGenerator) signingKey(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error) {
	if g.SigningKeyGenerator == nil {
		signingKey, method, signingKeyID, err := g.SigningKeyGenerator(grantType, client)
		if err != nil {
			return nil, nil, "", err
		}

		return signingKey, method, signingKeyID, nil
	}

	if g.SigningKey == nil {
		return nil, nil, "", ErrMissingSigningKey
	}

	if g.SigningKeyMethod == nil {
		return nil, nil, "", ErrMissingSigningMethod
	}

	return g.SigningKey, g.SigningKeyMethod, g.SigningKeyID, nil
}

func (g *JWTAccessTokenGenerator) jwtID() (string, error) {
	return common.GenerateRandString(DefaultJwtIDLength, common.AlphaNum)
}
