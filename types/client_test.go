package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClientAuthMethod(t *testing.T) {
	m := NewClientAuthMethod("password")
	assert.IsType(t, ClientAuthMethod(""), m)
	assert.Equal(t, "password", m.String())

	m = NewClientAuthMethod("client_secret_basic")
	assert.True(t, m.IsBasic())

	m = NewClientAuthMethod("client_secret_post")
	assert.True(t, m.IsPOST())

	m = NewClientAuthMethod("none")
	assert.True(t, m.IsNone())
}
