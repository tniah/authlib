package codegen

import (
	"github.com/tniah/authlib/models"
	"time"
)

const (
	DefaultCodeExpiresIn  = 5 * time.Minute
	DefaultAuthCodeLength = 48
)

type (
	Options struct {
		codeLength          int
		expiresIn           time.Duration
		expiresInGenerator  ExpiresInGenerator
		randStringGenerator RandStringGenerator
	}

	ExpiresInGenerator func(grantType string, client models.Client) (time.Duration, error)

	RandStringGenerator func(grantType string, client models.Client) (string, error)
)

func NewOptions() *Options {
	return &Options{
		codeLength: DefaultAuthCodeLength,
		expiresIn:  DefaultCodeExpiresIn,
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
