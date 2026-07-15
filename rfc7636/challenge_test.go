package rfc7636

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateS256CodeChallenge(t *testing.T) {
	t.Run("known_rfc_vector", func(t *testing.T) {
		// RFC 7636 Appendix B test vector
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		assert.Equal(t, expected, CreateS256CodeChallenge(verifier))
	})

	t.Run("idempotent", func(t *testing.T) {
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		assert.Equal(t, CreateS256CodeChallenge(verifier), CreateS256CodeChallenge(verifier))
	})
}

func TestValidateCodeVerifierPattern(t *testing.T) {
	t.Run("valid_min_length", func(t *testing.T) {
		assert.True(t, ValidateCodeVerifierPattern(strings.Repeat("a", 43)))
	})

	t.Run("valid_max_length", func(t *testing.T) {
		assert.True(t, ValidateCodeVerifierPattern(strings.Repeat("a", 128)))
	})

	t.Run("valid_all_allowed_chars", func(t *testing.T) {
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		assert.True(t, ValidateCodeVerifierPattern(verifier))
	})

	t.Run("invalid_too_short", func(t *testing.T) {
		assert.False(t, ValidateCodeVerifierPattern(strings.Repeat("a", 42)))
	})

	t.Run("invalid_too_long", func(t *testing.T) {
		assert.False(t, ValidateCodeVerifierPattern(strings.Repeat("a", 129)))
	})

	t.Run("invalid_chars", func(t *testing.T) {
		assert.False(t, ValidateCodeVerifierPattern(strings.Repeat("@", 43)))
	})

	t.Run("empty", func(t *testing.T) {
		assert.False(t, ValidateCodeVerifierPattern(""))
	})
}
