package rfc9068

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const DefaultExpiresIn = time.Minute * 60

var (
	ErrMissingIssuer           = errors.New("\"issuer\" or \"issuerGenerator\" is required")
	ErrMissingExpiresIn        = errors.New("\"expiresIn\" or \"expiresInGenerator\" is required")
	ErrMissingSigningKey       = errors.New("\"signingKey\" or \"signingKeyGenerator\" is required")
	ErrMissingSigningKeyMethod = errors.New("\"signingKeyMethod\" is required")
)

type GeneratorConfig struct {
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

func NewGeneratorConfig() *GeneratorConfig {
	return &GeneratorConfig{expiresIn: DefaultExpiresIn}
}

func (cfg *GeneratorConfig) SetIssuer(iss string) *GeneratorConfig {
	cfg.issuer = iss
	return cfg
}

func (cfg *GeneratorConfig) SetIssuerGenerator(fn IssuerGenerator) *GeneratorConfig {
	cfg.issuerGenerator = fn
	return cfg
}

func (cfg *GeneratorConfig) SetExpiresIn(exp time.Duration) *GeneratorConfig {
	cfg.expiresIn = exp
	return cfg
}

func (cfg *GeneratorConfig) SetExpiresInGenerator(fn ExpiresInGenerator) *GeneratorConfig {
	cfg.expiresInGenerator = fn
	return cfg
}

func (cfg *GeneratorConfig) SetSigningKey(key []byte, method jwt.SigningMethod, keyID ...string) *GeneratorConfig {
	cfg.signingKey = key
	cfg.signingKeyMethod = method

	if len(keyID) > 0 {
		cfg.signingKeyID = keyID[0]
	}

	return cfg
}

func (cfg *GeneratorConfig) SetSigningKeyGenerator(fn SigningKeyGenerator) *GeneratorConfig {
	cfg.signingKeyGenerator = fn
	return cfg
}

func (cfg *GeneratorConfig) SetExtraClaimGenerator(fn ExtraClaimGenerator) *GeneratorConfig {
	cfg.extraClaimGenerator = fn
	return cfg
}

func (cfg *GeneratorConfig) SetJWTIDGenerator(fn JWTIDGenerator) *GeneratorConfig {
	cfg.jwtIDGenerator = fn
	return cfg
}

func (cfg *GeneratorConfig) ValidateConfig() error {
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
