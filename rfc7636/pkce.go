package rfc7636

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
)

type ProofKeyForCodeExchangeFlow struct {
	*Options
}

func New(opts ...*Options) *ProofKeyForCodeExchangeFlow {
	if len(opts) > 0 {
		return &ProofKeyForCodeExchangeFlow{opts[0]}
	}

	defaultOpts := NewOptions()
	return &ProofKeyForCodeExchangeFlow{defaultOpts}
}

func Must(opts ...*Options) (*ProofKeyForCodeExchangeFlow, error) {
	if len(opts) > 0 {
		if err := opts[0].ValidateOptions(); err != nil {
			return nil, err
		}
	}

	return New(opts...), nil
}

func (f *ProofKeyForCodeExchangeFlow) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	if r.CodeChallenge == "" && r.CodeChallengeMethod.IsEmpty() {
		return nil
	}

	if r.CodeChallenge == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"code_challenge\" in request")
	}

	if !r.CodeChallengeMethod.IsEmpty() && !r.CodeChallengeMethod.IsS256() && !r.CodeChallengeMethod.IsPlain() {
		return autherrors.InvalidRequestError().WithDescription("Unsupported \"code_challenge_method\"")
	}

	return nil
}

func (f *ProofKeyForCodeExchangeFlow) ValidateTokenRequest(r *requests.TokenRequest) error {
	if f.required && r.ClientAuthMethod.IsNone() && r.CodeVerifier == "" {
		return autherrors.InvalidRequestError().WithDescription("missing \"code_verifier\" in request")
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
		return autherrors.InvalidGrantError().WithDescription("Code verifier validation failed")
	}

	return nil
}

func (f *ProofKeyForCodeExchangeFlow) ProcessAuthorizationCode(r *requests.AuthorizationRequest, authCode models.AuthorizationCode, params map[string]interface{}) error {
	authCode.SetCodeChallenge(r.Nonce)
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
