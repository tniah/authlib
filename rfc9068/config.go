package rfc9068

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tniah/authlib/models"
	"time"
)

var (
	ErrMissingIssuer           = errors.New("\"issuer\" or \"issuerGenerator\" is required")
	ErrMissingExpiresIn        = errors.New("\"expiresIn\" or \"expiresInGenerator\" is required")
	ErrMissingSigningKey       = errors.New("\"signingKey\" or \"signingKeyGenerator\" is required")
	ErrMissingSigningKeyMethod = errors.New("\"signingKeyMethod\" is required")
)

type (
	JWTAccessTokenGeneratorConfig struct {
		issuer              string
		issuerGenerator     IssuerGenerator
		expiresIn           time.Duration
		expiresInGenerator  ExpiresInGenerator
		signingKey          []byte
		signingKeyMethod    jwt.SigningMethod
		signingKeyID        string
		signingKeyGenerator SigningKeyGenerator
		extraClaimGenerator ExtraClaimGenerator
		jwtIDGenerator      JWTIDGenerator
	}

	IssuerGenerator func(grantType string, client models.Client) (string, error)

	ExpiresInGenerator func(grantType string, client models.Client) (time.Duration, error)

	SigningKeyGenerator func(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error)

	ExtraClaimGenerator func(grantType string, client models.Client, user models.User, scopes []string) (map[string]interface{}, error)

	JWTIDGenerator func(grantType string, client models.Client) (string, error)
)

func NewJWTAccessTokenGeneratorConfig() *JWTAccessTokenGeneratorConfig {
	return &JWTAccessTokenGeneratorConfig{
		expiresIn: DefaultExpiresIn,
	}
}

func (opt *JWTAccessTokenGeneratorConfig) SetIssuer(iss string) *JWTAccessTokenGeneratorConfig {
	opt.issuer = iss
	return opt
}

func (opt *JWTAccessTokenGeneratorConfig) SetIssuerGenerator(fn IssuerGenerator) *JWTAccessTokenGeneratorConfig {
	opt.issuerGenerator = fn
	return opt
}

func (opt *JWTAccessTokenGeneratorConfig) SetExpiresIn(exp time.Duration) *JWTAccessTokenGeneratorConfig {
	opt.expiresIn = exp
	return opt
}

func (opt *JWTAccessTokenGeneratorConfig) SetExpiresInGenerator(fn ExpiresInGenerator) *JWTAccessTokenGeneratorConfig {
	opt.expiresInGenerator = fn
	return opt
}

func (opt *JWTAccessTokenGeneratorConfig) SetSigningKey(key []byte, method jwt.SigningMethod, id ...string) *JWTAccessTokenGeneratorConfig {
	opt.signingKey = key
	opt.signingKeyMethod = method

	if len(id) > 0 {
		opt.signingKeyID = id[0]
	}

	return opt
}

func (opt *JWTAccessTokenGeneratorConfig) SetSigningKeyGenerator(fn SigningKeyGenerator) *JWTAccessTokenGeneratorConfig {
	opt.signingKeyGenerator = fn
	return opt
}

func (opt *JWTAccessTokenGeneratorConfig) SetExtraClaimGenerator(fn ExtraClaimGenerator) *JWTAccessTokenGeneratorConfig {
	opt.extraClaimGenerator = fn
	return opt
}

func (opt *JWTAccessTokenGeneratorConfig) SetJWTIDGenerator(fn JWTIDGenerator) *JWTAccessTokenGeneratorConfig {
	opt.jwtIDGenerator = fn
	return opt
}

func (opt *JWTAccessTokenGeneratorConfig) Validate() error {
	if opt.issuer == "" && opt.issuerGenerator == nil {
		return ErrMissingIssuer
	}

	if opt.expiresIn == 0 && opt.expiresInGenerator == nil {
		return ErrMissingExpiresIn
	}

	if opt.signingKey == nil && opt.signingKeyGenerator == nil {
		return ErrMissingSigningKey
	}

	if opt.signingKey != nil && opt.signingKeyMethod == nil {
		return ErrMissingSigningKeyMethod
	}

	return nil
}
