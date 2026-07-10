package authorizationcode

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	autherrors "github.com/tniah/authlib/errors"
)

const DefaultExpiresIn = time.Minute * 60

type Config struct {
	requireNonce        bool
	issuer              string
	issuerGenerator     IssuerGenerator
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	signingKey          []byte
	signingKeyMethod    jwt.SigningMethod
	signingKeyID        string
	signingKeyGenerator SigningKeyGenerator
	extraClaimGenerator ExtraClaimGenerator
	existNonce          ExistNonce
}

func NewConfig() *Config {
	return &Config{
		requireNonce: true,
		expiresIn:    DefaultExpiresIn,
	}
}

func (cfg *Config) SetRequireNonce(value bool) *Config {
	cfg.requireNonce = value
	return cfg
}

func (cfg *Config) SetIssuer(iss string) *Config {
	cfg.issuer = iss
	return cfg
}

func (cfg *Config) SetIssuerGenerator(fn IssuerGenerator) *Config {
	cfg.issuerGenerator = fn
	return cfg
}

func (cfg *Config) SetExpiresIn(exp time.Duration) *Config {
	cfg.expiresIn = exp
	return cfg
}

func (cfg *Config) SetExpiresInGenerator(fn ExpiresInGenerator) *Config {
	cfg.expiresInGenerator = fn
	return cfg
}

func (cfg *Config) SetSigningKey(key []byte, method jwt.SigningMethod, keyID ...string) *Config {
	cfg.signingKey = key
	cfg.signingKeyMethod = method

	if len(keyID) > 0 {
		cfg.signingKeyID = keyID[0]
	}

	return cfg
}

func (cfg *Config) SetSigningKeyGenerator(fn SigningKeyGenerator) *Config {
	cfg.signingKeyGenerator = fn
	return cfg
}

func (cfg *Config) SetExtraClaimGenerator(fn ExtraClaimGenerator) *Config {
	cfg.extraClaimGenerator = fn
	return cfg
}

func (cfg *Config) ValidateConfig() error {
	if cfg.issuer == "" && cfg.issuerGenerator == nil {
		return autherrors.ErrMissingIssuer
	}

	if cfg.expiresIn == 0 && cfg.expiresInGenerator == nil {
		return autherrors.ErrMissingExpiresIn
	}

	if cfg.signingKey == nil && cfg.signingKeyGenerator == nil {
		return autherrors.ErrMissingSigningKey
	}

	if cfg.signingKey != nil && cfg.signingKeyMethod == nil {
		return autherrors.ErrMissingSigningKeyMethod
	}

	return nil
}
