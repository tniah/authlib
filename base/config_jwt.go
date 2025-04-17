package base

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

type JWTConfig struct {
	issuer              string
	issuerGenerator     IssuerGenerator
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	signingKey          []byte
	signingKeyMethod    jwt.SigningMethod
	signingKeyID        string
	signingKeyGenerator SigningKeyGenerator
	extraClaimGenerator ExtraClaimGenerator
}

type IssuerGenerator func(client models.Client) string

type ExpiresInGenerator func(grantType string, client models.Client) time.Duration

type SigningKeyGenerator func(client models.Client) ([]byte, jwt.SigningMethod, string)

type ExtraClaimGenerator func(grantType string, client models.Client, user models.User, scopes []string) (map[string]interface{}, error)

func (cfg *JWTConfig) Issuer() string {
	return cfg.issuer
}

func (cfg *JWTConfig) SetIssuer(iss string) *JWTConfig {
	cfg.issuer = iss
	return cfg
}

func (cfg *JWTConfig) IssuerGenerator() IssuerGenerator {
	return cfg.issuerGenerator
}

func (cfg *JWTConfig) SetIssuerGenerator(fn IssuerGenerator) *JWTConfig {
	cfg.issuerGenerator = fn
	return cfg
}

func (cfg *JWTConfig) ExpiresIn() time.Duration {
	return cfg.expiresIn
}

func (cfg *JWTConfig) SetExpiresIn(exp time.Duration) *JWTConfig {
	cfg.expiresIn = exp
	return cfg
}

func (cfg *JWTConfig) ExpiresInGenerator() ExpiresInGenerator {
	return cfg.expiresInGenerator
}

func (cfg *JWTConfig) SetExpiresInGenerator(fn ExpiresInGenerator) *JWTConfig {
	cfg.expiresInGenerator = fn
	return cfg
}

func (cfg *JWTConfig) SigningKey() []byte {
	return cfg.signingKey
}

func (cfg *JWTConfig) SigningKeyMethod() jwt.SigningMethod {
	return cfg.signingKeyMethod
}

func (cfg *JWTConfig) SigningKeyID() string {
	return cfg.signingKeyID
}

func (cfg *JWTConfig) SetSigningKey(key []byte, method jwt.SigningMethod, id ...string) *JWTConfig {
	cfg.signingKey = key
	cfg.signingKeyMethod = method

	if len(id) > 0 {
		cfg.signingKeyID = id[0]
	}

	return cfg
}

func (cfg *JWTConfig) SigningKeyGenerator() SigningKeyGenerator {
	return cfg.signingKeyGenerator
}

func (cfg *JWTConfig) SetSigningKeyGenerator(fn SigningKeyGenerator) *JWTConfig {
	cfg.signingKeyGenerator = fn
	return cfg
}

func (cfg *JWTConfig) ExtraClaimGenerator() ExtraClaimGenerator {
	return cfg.extraClaimGenerator
}

func (cfg *JWTConfig) SetExtraClaimGenerator(fn ExtraClaimGenerator) *JWTConfig {
	cfg.extraClaimGenerator = fn
	return cfg
}

func (cfg *JWTConfig) ValidateConfig() error {
	if cfg.issuer == "" && cfg.issuerGenerator == nil {
		return ErrMissingIssuer
	}

	if cfg.expiresIn == 0 && cfg.expiresInGenerator == nil {
		return ErrMissingExpiresIn
	}

	if cfg.signingKey == nil && cfg.signingKeyGenerator == nil {
		return ErrMissingSigningKey
	}

	if cfg.signingKey != nil && cfg.signingKeyMethod == nil {
		return ErrMissingSigningKeyMethod
	}

	return nil
}
