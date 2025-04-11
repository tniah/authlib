package rfc6750

import "time"

const (
	TokenTypeBearer              = "Bearer"
	DefaultExpiresIn             = time.Minute * 60
	DefaultTokenLength           = 48
	DefaultRefreshTokenExpiresIn = time.Hour * 24
)

type TokenGeneratorOptions struct {
	tokenLength         int
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	randStringGenerator RandStringGenerator
}

func NewTokenGeneratorOptions() *TokenGeneratorOptions {
	return &TokenGeneratorOptions{
		tokenLength: DefaultTokenLength,
		expiresIn:   DefaultExpiresIn,
	}
}

func (opts *TokenGeneratorOptions) SetExpiresIn(exp time.Duration) *TokenGeneratorOptions {
	opts.expiresIn = exp
	return opts
}

func (opts *TokenGeneratorOptions) SetExpiresInGenerator(fn ExpiresInGenerator) *TokenGeneratorOptions {
	opts.expiresInGenerator = fn
	return opts
}

func (opts *TokenGeneratorOptions) SetRandStringGenerator(fn RandStringGenerator) *TokenGeneratorOptions {
	opts.randStringGenerator = fn
	return opts
}
