package rfc9068

import (
	"github.com/tniah/authlib/base"
	"github.com/tniah/authlib/models"
)

type JWTAccessTokenGeneratorConfig struct {
	*base.JWTConfig
	jwtIDGenerator JWTIDGenerator
}

type JWTIDGenerator func(grantType string, client models.Client) (string, error)

func NewJWTAccessTokenGeneratorConfig() *JWTAccessTokenGeneratorConfig {
	cfg := &JWTAccessTokenGeneratorConfig{
		JWTConfig: &base.JWTConfig{},
	}

	cfg.SetExpiresIn(DefaultExpiresIn)
	return cfg
}

func (cfg *JWTAccessTokenGeneratorConfig) JWTIDGenerator() JWTIDGenerator {
	return cfg.jwtIDGenerator
}

func (cfg *JWTAccessTokenGeneratorConfig) SetJWTIDGenerator(fn JWTIDGenerator) *JWTAccessTokenGeneratorConfig {
	cfg.jwtIDGenerator = fn
	return cfg
}
