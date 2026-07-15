package rfc7636

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tniah/authlib/types"
)

func TestNewOptions(t *testing.T) {
	opts := NewOptions()
	assert.True(t, opts.required)
	assert.Equal(t, types.CodeChallengeMethodS256, opts.defaultCodeChallengeMethod)
}

func TestOptions_SetRequired(t *testing.T) {
	t.Run("sets_true", func(t *testing.T) {
		opts := NewOptions()
		result := opts.SetRequired(true)
		assert.Equal(t, opts, result)
		assert.True(t, opts.required)
	})

	t.Run("sets_false", func(t *testing.T) {
		opts := NewOptions()
		result := opts.SetRequired(false)
		assert.Equal(t, opts, result)
		assert.False(t, opts.required)
	})
}

func TestOptions_SetDefaultCodeChallengeMethod(t *testing.T) {
	t.Run("sets_s256", func(t *testing.T) {
		opts := NewOptions()
		result := opts.SetDefaultCodeChallengeMethod(types.CodeChallengeMethodS256)
		assert.Equal(t, opts, result)
		assert.Equal(t, types.CodeChallengeMethodS256, opts.defaultCodeChallengeMethod)
	})

	t.Run("sets_plain", func(t *testing.T) {
		opts := NewOptions()
		result := opts.SetDefaultCodeChallengeMethod(types.CodeChallengeMethodPlain)
		assert.Equal(t, opts, result)
		assert.Equal(t, types.CodeChallengeMethodPlain, opts.defaultCodeChallengeMethod)
	})
}

func TestOptions_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		assert.NoError(t, NewOptions().Validate())
	})

	t.Run("error_when_method_empty", func(t *testing.T) {
		opts := NewOptions().SetDefaultCodeChallengeMethod("")
		assert.ErrorIs(t, opts.Validate(), ErrMissingDefaultCodeChallengeMethod)
	})
}
