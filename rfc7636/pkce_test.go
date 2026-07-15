package rfc7636

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tniah/authlib/integrations/sql"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
)

// RFC 7636 Appendix B test vector.
const (
	testVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestNew(t *testing.T) {
	t.Run("no_opts_uses_defaults", func(t *testing.T) {
		f := New()
		assert.NotNil(t, f)
		assert.True(t, f.required)
		assert.Equal(t, types.CodeChallengeMethodS256, f.defaultCodeChallengeMethod)
	})

	t.Run("with_opts", func(t *testing.T) {
		opts := NewOptions().SetRequired(false)
		f := New(opts)
		assert.False(t, f.required)
	})

	t.Run("nil_opts_uses_defaults", func(t *testing.T) {
		f := New(nil)
		assert.NotNil(t, f)
		assert.True(t, f.required)
	})
}

func TestMust(t *testing.T) {
	t.Run("no_opts_uses_defaults", func(t *testing.T) {
		f, err := Must()
		require.NoError(t, err)
		assert.NotNil(t, f)
		assert.True(t, f.required)
	})

	t.Run("with_valid_opts", func(t *testing.T) {
		opts := NewOptions().SetRequired(false)
		f, err := Must(opts)
		require.NoError(t, err)
		assert.False(t, f.required)
	})

	t.Run("nil_opts_uses_defaults", func(t *testing.T) {
		f, err := Must(nil)
		require.NoError(t, err)
		assert.NotNil(t, f)
	})

	t.Run("error_when_method_empty", func(t *testing.T) {
		opts := NewOptions().SetDefaultCodeChallengeMethod("")
		f, err := Must(opts)
		assert.ErrorIs(t, err, ErrMissingDefaultCodeChallengeMethod)
		assert.Nil(t, f)
	})
}

func TestProofKeyForCodeExchangeFlow_ValidateAuthorizationRequest(t *testing.T) {
	f := New()

	t.Run("no_pkce_params_skips", func(t *testing.T) {
		r := &requests.AuthorizationRequest{}
		assert.NoError(t, f.ValidateAuthorizationRequest(r))
	})

	t.Run("only_method_missing_challenge", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallengeMethod: types.CodeChallengeMethodS256,
		}
		err := f.ValidateAuthorizationRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_challenge")
	})

	t.Run("unsupported_method", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testChallenge,
			CodeChallengeMethod: types.NewCodeChallengeMethod("unsupported"),
		}
		err := f.ValidateAuthorizationRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_challenge_method")
	})

	t.Run("valid_s256", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testChallenge,
			CodeChallengeMethod: types.CodeChallengeMethodS256,
		}
		assert.NoError(t, f.ValidateAuthorizationRequest(r))
	})

	t.Run("valid_plain", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testVerifier,
			CodeChallengeMethod: types.CodeChallengeMethodPlain,
		}
		assert.NoError(t, f.ValidateAuthorizationRequest(r))
	})

	t.Run("valid_challenge_without_method", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge: testChallenge,
		}
		assert.NoError(t, f.ValidateAuthorizationRequest(r))
	})
}

func TestProofKeyForCodeExchangeFlow_ValidateTokenRequest(t *testing.T) {
	f := New()

	t.Run("required_public_client_no_verifier", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientNoneAuthentication,
		}
		err := f.ValidateTokenRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_verifier")
	})

	t.Run("nil_auth_code", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
		}
		err := f.ValidateTokenRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization code")
	})

	t.Run("no_challenge_no_verifier_skips", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode:         &sql.AuthorizationCode{},
		}
		assert.NoError(t, f.ValidateTokenRequest(r))
	})

	t.Run("challenge_present_no_verifier", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode:         &sql.AuthorizationCode{CodeChallenge: testChallenge},
		}
		err := f.ValidateTokenRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_verifier")
	})

	t.Run("invalid_verifier_pattern", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode:         &sql.AuthorizationCode{CodeChallenge: testChallenge},
			CodeVerifier:     strings.Repeat("@", 43),
		}
		err := f.ValidateTokenRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_verifier")
	})

	t.Run("s256_valid", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode: &sql.AuthorizationCode{
				CodeChallenge:       testChallenge,
				CodeChallengeMethod: string(types.CodeChallengeMethodS256),
			},
			CodeVerifier: testVerifier,
		}
		assert.NoError(t, f.ValidateTokenRequest(r))
	})

	t.Run("s256_invalid", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode: &sql.AuthorizationCode{
				CodeChallenge:       testChallenge,
				CodeChallengeMethod: string(types.CodeChallengeMethodS256),
			},
			CodeVerifier: strings.Repeat("a", 43),
		}
		err := f.ValidateTokenRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code verifier")
	})

	t.Run("plain_valid", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode: &sql.AuthorizationCode{
				CodeChallenge:       testVerifier,
				CodeChallengeMethod: string(types.CodeChallengeMethodPlain),
			},
			CodeVerifier: testVerifier,
		}
		assert.NoError(t, f.ValidateTokenRequest(r))
	})

	t.Run("plain_invalid", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode: &sql.AuthorizationCode{
				CodeChallenge:       testVerifier,
				CodeChallengeMethod: string(types.CodeChallengeMethodPlain),
			},
			CodeVerifier: strings.Repeat("b", 43),
		}
		err := f.ValidateTokenRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code verifier")
	})

	t.Run("empty_method_falls_back_to_default_s256", func(t *testing.T) {
		r := &requests.TokenRequest{
			ClientAuthMethod: types.ClientBasicAuthentication,
			AuthCode: &sql.AuthorizationCode{
				CodeChallenge: testChallenge,
				// CodeChallengeMethod intentionally empty — should fall back to S256
			},
			CodeVerifier: testVerifier,
		}
		assert.NoError(t, f.ValidateTokenRequest(r))
	})
}

func TestProofKeyForCodeExchangeFlow_ProcessAuthorizationCode(t *testing.T) {
	f := New()

	t.Run("nil_auth_code", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testChallenge,
			CodeChallengeMethod: types.CodeChallengeMethodS256,
		}
		err := f.ProcessAuthorizationCode(r, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization code")
	})

	t.Run("stores_challenge_and_method", func(t *testing.T) {
		r := &requests.AuthorizationRequest{
			CodeChallenge:       testChallenge,
			CodeChallengeMethod: types.CodeChallengeMethodS256,
		}
		authCode := &sql.AuthorizationCode{}
		err := f.ProcessAuthorizationCode(r, authCode, nil)
		require.NoError(t, err)
		assert.Equal(t, testChallenge, authCode.GetCodeChallenge())
		assert.Equal(t, types.CodeChallengeMethodS256, authCode.GetCodeChallengeMethod())
	})
}
