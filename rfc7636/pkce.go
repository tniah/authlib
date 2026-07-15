package rfc7636

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"github.com/tniah/authlib/utils"
)

// ProofKeyForCodeExchangeFlow implements PKCE (RFC 7636) as an extension for
// the Authorization Code grant. Register it via cfg.RegisterExtension.
type ProofKeyForCodeExchangeFlow struct {
	*Options
}

// New returns a ProofKeyForCodeExchangeFlow with the given Options, or secure
// defaults if none are provided. Options are not validated — use Must to
// validate at construction time.
func New(opts ...*Options) *ProofKeyForCodeExchangeFlow {
	if len(opts) > 0 {
		return &ProofKeyForCodeExchangeFlow{opts[0]}
	}

	defaultOpts := NewOptions()
	return &ProofKeyForCodeExchangeFlow{defaultOpts}
}

// Must is like New but calls Validate on the resolved Options and returns an
// error if they are invalid.
func Must(opts ...*Options) (*ProofKeyForCodeExchangeFlow, error) {
	o := NewOptions()
	if len(opts) > 0 {
		o = opts[0]
	}

	if err := o.Validate(); err != nil {
		return nil, err
	}

	return &ProofKeyForCodeExchangeFlow{o}, nil
}

// ValidateAuthorizationRequest checks that the PKCE parameters in the
// authorization request are well-formed. It is a no-op when neither
// code_challenge nor code_challenge_method is present.
func (f *ProofKeyForCodeExchangeFlow) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	if r.CodeChallenge == "" && r.CodeChallengeMethod.IsEmpty() {
		return nil
	}

	if r.CodeChallenge == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"code_challenge\" in request")
	}

	if !r.CodeChallengeMethod.IsEmpty() && !r.CodeChallengeMethod.IsS256() && !r.CodeChallengeMethod.IsPlain() {
		return autherrors.InvalidRequestError().WithDescription("unsupported \"code_challenge_method\"")
	}

	return nil
}

// ValidateTokenRequest verifies the code_verifier against the stored
// code_challenge. It enforces PKCE for public clients when required is true.
func (f *ProofKeyForCodeExchangeFlow) ValidateTokenRequest(r *requests.TokenRequest) error {
	if f.required && r.ClientAuthMethod.IsNone() && r.CodeVerifier == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"code_verifier\" in request")
	}

	if utils.IsNil(r.AuthCode) {
		return autherrors.InvalidRequestError().WithDescription("missing authorization code")
	}

	challenge := r.AuthCode.GetCodeChallenge()
	if challenge == "" && r.CodeVerifier == "" {
		return nil
	}

	if r.CodeVerifier == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"code_verifier\" in request")
	}

	if valid := ValidateCodeVerifierPattern(r.CodeVerifier); !valid {
		return autherrors.InvalidRequestError().WithDescription("\"code_verifier\" does not match pattern")
	}

	method := r.AuthCode.GetCodeChallengeMethod()
	if method.IsEmpty() {
		method = f.defaultCodeChallengeMethod
	}

	if valid := f.validateCodeVerifier(method, r.CodeVerifier, challenge); !valid {
		return autherrors.InvalidGrantError().WithDescription("code verifier validation failed")
	}

	return nil
}

// ProcessAuthorizationCode stores the PKCE parameters from the authorization
// request into the authorization code before it is persisted.
func (f *ProofKeyForCodeExchangeFlow) ProcessAuthorizationCode(r *requests.AuthorizationRequest, authCode models.AuthorizationCode, params map[string]any) error {
	authCode.SetCodeChallenge(r.CodeChallenge)
	authCode.SetCodeChallengeMethod(r.CodeChallengeMethod)
	return nil
}

func (f *ProofKeyForCodeExchangeFlow) validateCodeVerifier(m types.CodeChallengeMethod, verifier, challenge string) bool {
	if m.IsS256() {
		return f.validateS256Challenge(verifier, challenge)
	}

	if m.IsPlain() {
		return f.validatePlainChallenge(verifier, challenge)
	}

	return false
}

func (f *ProofKeyForCodeExchangeFlow) validatePlainChallenge(verifier, challenge string) bool {
	return verifier == challenge
}

func (f *ProofKeyForCodeExchangeFlow) validateS256Challenge(verifier, challenge string) bool {
	return CreateS256CodeChallenge(verifier) == challenge
}
