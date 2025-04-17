package authorizationcode

import (
	"github.com/tniah/authlib/base"
	"github.com/tniah/authlib/requests"
)

type Config struct {
	requireNonce bool
	existNonce   ExistNonce
	*base.JWTConfig
}

type ExistNonce func(nonce string, r *requests.AuthorizationRequest) bool

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
