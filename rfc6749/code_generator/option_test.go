package codegen

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestOptions(t *testing.T) {
	opts := NewOptions()
	assert.Equal(t, DefaultCodeLength, opts.codeLength)
	assert.Equal(t, DefaultExpiresIn, opts.expiresIn)

	opts.SetCodeLength(10)
	assert.Equal(t, 10, opts.codeLength)

	opts.SetExpiresIn(60 * time.Second)
	assert.Equal(t, 60*time.Second, opts.expiresIn)
}
