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
	assert.True(t, m.IsBasicAuthentication())

	m = NewClientAuthMethod("client_secret_post")
	assert.True(t, m.IsPostAuthentication())

	m = NewClientAuthMethod("none")
	assert.True(t, m.IsNoneAuthentication())
}
