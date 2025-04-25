package rfc7636

import (
	"errors"
	"github.com/tniah/authlib/types"
)

var ErrMissingDefaultCodeChallengeMethod = errors.New("missing default code challenge method")

type Options struct {
	required                   bool
	defaultCodeChallengeMethod types.CodeChallengeMethod
}

func NewOptions() *Options {
	return &Options{
		required:                   true,
		defaultCodeChallengeMethod: types.CodeChallengeMethodPlain,
	}
}

func (opts *Options) SetRequired(value bool) *Options {
	opts.required = value
	return opts
}

func (opts *Options) SetDefaultCodeChallengeMethod(m types.CodeChallengeMethod) *Options {
	opts.defaultCodeChallengeMethod = m
	return opts
}

func (opts *Options) ValidateOptions() error {
	if opts.defaultCodeChallengeMethod.IsEmpty() {
		return ErrMissingDefaultCodeChallengeMethod
	}

	return nil
}
