package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCodeChallengeMethod(t *testing.T) {
	m := NewCodeChallengeMethod("test")
	assert.IsType(t, CodeChallengeMethod(""), m)
	assert.Equal(t, "test", m.String())
	assert.False(t, m.IsEmpty())
	assert.True(t, m.Equal(NewCodeChallengeMethod("test")))

	assert.True(t, CodeChallengeMethodS256.IsS256())
	assert.False(t, CodeChallengeMethodS256.IsPlain())
	assert.True(t, CodeChallengeMethodPlain.IsPlain())
	assert.False(t, CodeChallengeMethodPlain.IsS256())
}
