package codegen

import (
	"time"
)

const (
	DefaultExpiresIn  = 5 * time.Minute
	DefaultCodeLength = 48
)

type Options struct {
	codeLength          int
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	randStringGenerator RandStringGenerator
	extraDataGenerator  ExtraDataGenerator
}

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
