package codegen

import (
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"time"
)

const (
	DefaultExpiresIn  = 5 * time.Minute
	DefaultCodeLength = 48
)

type (
	Options struct {
		codeLength          int
		expiresIn           time.Duration
		expiresInGenerator  ExpiresInGenerator
		randStringGenerator RandStringGenerator
		extraDataGenerator  ExtraDataGenerator
	}

	ExpiresInGenerator func(grantType string, client models.Client) (time.Duration, error)

	RandStringGenerator func(grantType string, client models.Client) (string, error)

	ExtraDataGenerator func(r *requests.AuthorizationRequest) (map[string]interface{}, error)
)

func NewOptions() *Options {
	return &Options{
		codeLength: DefaultCodeLength,
		expiresIn:  DefaultExpiresIn,
	}
}

func (opts *Options) SetCodeLength(length int) *Options {
	opts.codeLength = length
	return opts
}

func (opts *Options) SetExpiresIn(l time.Duration) *Options {
	opts.expiresIn = l
	return opts
}

func (opts *Options) SetExpiresInGenerator(fn ExpiresInGenerator) *Options {
	opts.expiresInGenerator = fn
	return opts
}

func (opts *Options) SetRandStringGenerator(fn RandStringGenerator) *Options {
	opts.randStringGenerator = fn
	return opts
}

func (opts *Options) SetExtraDataGenerator(fn ExtraDataGenerator) *Options {
	opts.extraDataGenerator = fn
	return opts
}
