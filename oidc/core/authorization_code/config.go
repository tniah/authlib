package authorizationcode

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

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
	}
}

func (cfg *Config) SetRequireNonce(value bool) *Config {
	cfg.requireNonce = value
	return cfg
}
