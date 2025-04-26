package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestScope(t *testing.T) {
	s := NewScope("test")
	assert.IsType(t, Scope(""), s)

	assert.False(t, s.IsEmpty())
	assert.Equal(t, "test", s.String())
	assert.True(t, ScopeOpenID.IsOpenID())
	assert.False(t, s.IsOpenID())
}

func TestScopes(t *testing.T) {
	scopes := NewScopes([]string{"openid", "profile"})
	assert.True(t, scopes.ContainOpenID())
	assert.False(t, scopes.Contain("test"))

	assert.Equal(t, []string{"openid", "profile"}, scopes.String())
}
