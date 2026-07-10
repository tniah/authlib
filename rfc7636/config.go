package rfc7636

import (
	"errors"

	"github.com/tniah/authlib/types"
)

var ErrMissingDefaultCodeChallengeMethod = errors.New("missing default code challenge method")

// Options configures PKCE (Proof Key for Code Exchange, RFC 7636) behavior.
type Options struct {
	// required forces public clients (none auth method) to always include a
	// code_verifier. Set to false to allow PKCE to be optional.
	required bool
	// defaultCodeChallengeMethod is used when the client omits
	// code_challenge_method from the authorization request.
	defaultCodeChallengeMethod types.CodeChallengeMethod
}

// NewOptions returns Options with secure defaults:
//   - PKCE is required for public clients.
//   - Default challenge method is S256 (SHA-256), per RFC 9700 §2.1.
func NewOptions() *Options {
	return &Options{
		required:                   true,
		defaultCodeChallengeMethod: types.CodeChallengeMethodS256,
	}
}

// SetRequired controls whether PKCE is mandatory for public clients.
func (opts *Options) SetRequired(value bool) *Options {
	opts.required = value
	return opts
}

// SetDefaultCodeChallengeMethod sets the fallback method when the authorization
// request omits code_challenge_method. Prefer S256 over plain.
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
