package authorizationcode

import (
	"github.com/tniah/authlib/base"
	"net/http"
)

type Config struct {
	requireNonce   bool
	nonceValidator NonceValidator
	*base.JWTConfig
}

type NonceValidator func(nonce string, r *http.Request) bool

func NewConfig() *Config {
	return &Config{
		requireNonce: true,
		JWTConfig:    &base.JWTConfig{},
	}
}

func (cfg *Config) SetRequireNonce(value bool) *Config {
	cfg.requireNonce = value
	return cfg
}
