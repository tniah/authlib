package common

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"time"
)

var ErrUnsupportedSigningMethod = errors.New("unsupported signing method")

const (
	JWTHeaderKid     = "kid"
	JWTClaimIssuedAt = "iat"
)

type (
	JWTToken struct {
		signingKeyID  string
		signingKey    interface{}
		signingMethod jwt.SigningMethod
	}

	JWTHeader map[string]interface{}
	JWTClaim  map[string]interface{}
)

func NewJWTToken(signingKey []byte, signingMethod jwt.SigningMethod, args ...string) (*JWTToken, error) {
	var keyID string
	if len(args) > 0 {
		keyID = args[0]
	}

	key, err := ParseSigningKey(signingKey, signingMethod)
	if err != nil {
		return nil, err
	}

	return &JWTToken{
		signingKeyID:  keyID,
		signingKey:    key,
		signingMethod: signingMethod,
	}, nil
}

func (t *JWTToken) KeyID() string {
	return t.signingKeyID
}

func (t *JWTToken) SigningKey() interface{} {
	return t.signingKey
}

func (t *JWTToken) SigningMethod() jwt.SigningMethod {
	return t.signingMethod
}

func (t *JWTToken) Generate(claims JWTClaim, headers JWTHeader) (string, error) {
	mapClaims := jwt.MapClaims{
		JWTClaimIssuedAt: jwt.NewNumericDate(time.Now()),
	}
	for k, _ := range claims {
		mapClaims[k] = claims[k]
	}

	token := jwt.NewWithClaims(t.signingMethod, mapClaims)
	for k, v := range headers {
		token.Header[k] = v
	}

	if t.signingKeyID != "" {
		token.Header[JWTHeaderKid] = t.signingKeyID
	}

	return token.SignedString(t.signingKey)
}

func ParseSigningKey(signingKey []byte, signingMethod jwt.SigningMethod) (interface{}, error) {
	alg := signingMethod.Alg()
	if strings.HasPrefix(alg, "ES") {
		return jwt.ParseECPrivateKeyFromPEM(signingKey)
	}

	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
		return jwt.ParseRSAPrivateKeyFromPEM(signingKey)
	}

	if strings.HasPrefix(alg, "HS") {
		return signingKey, nil
	}

	if strings.HasPrefix(alg, "Ed") {
		return jwt.ParseEdPrivateKeyFromPEM(signingKey)
	}

	return nil, ErrUnsupportedSigningMethod
}
