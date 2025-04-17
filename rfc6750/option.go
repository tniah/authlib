package rfc6750

import (
	"errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"time"
)

var (
	ErrNilAccessTokenGenerator  = errors.New("access token generator is nil")
	ErrNilRefreshTokenGenerator = errors.New("refresh token generator is nil")
)

const (
	DefaultExpiresIn   = time.Minute * 60
	DefaultTokenLength = 48
)

type (
	BearerTokenGeneratorOptions struct {
		atGen TokenGenerator
		rfGen TokenGenerator
	}

	TokenGenerator interface {
		Generate(token models.Token, r *requests.TokenRequest) error
	}
)

func NewBearerTokenGeneratorOptions() *BearerTokenGeneratorOptions {
	return &BearerTokenGeneratorOptions{
		atGen: NewOpaqueAccessTokenGenerator(),
		rfGen: NewOpaqueRefreshTokenGenerator(),
	}
}

func (cfg *BearerTokenGeneratorOptions) SetAccessTokenGenerator(gen TokenGenerator) *BearerTokenGeneratorOptions {
	cfg.atGen = gen
	return cfg
}

func (cfg *BearerTokenGeneratorOptions) SetRefreshTokenGenerator(gen TokenGenerator) *BearerTokenGeneratorOptions {
	cfg.rfGen = gen
	return cfg
}

func (cfg *BearerTokenGeneratorOptions) Validate() error {
	if cfg.atGen == nil {
		return ErrNilAccessTokenGenerator
	}

	if cfg.rfGen == nil {
		return ErrNilRefreshTokenGenerator
	}

	return nil
}

type (
	TokenGeneratorOptions struct {
		tokenLength         int
		expiresIn           time.Duration
		expiresInGenerator  ExpiresInGenerator
		randStringGenerator RandStringGenerator
	}

	ExpiresInGenerator func(grantType string, client models.Client) (time.Duration, error)

	RandStringGenerator func(grantType string, client models.Client) (string, error)
)

func NewTokenGeneratorOptions() *TokenGeneratorOptions {
	return &TokenGeneratorOptions{
		tokenLength: DefaultTokenLength,
		expiresIn:   DefaultExpiresIn,
	}
}

func (opts *TokenGeneratorOptions) SetTokenLength(l int) *TokenGeneratorOptions {
	opts.tokenLength = l
	return opts
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
