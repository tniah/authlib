package codegen

import (
	"github.com/stretchr/testify/assert"
	codegen "github.com/tniah/authlib/mocks/rfc6749/code_generator"
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

	opts.SetExpiresInGenerator(codegen.NewMockExpiresInGenerator(t).Execute)
	assert.NotNil(t, opts.expiresInGenerator)

	opts.SetRandStringGenerator(codegen.NewMockRandStringGenerator(t).Execute)
	assert.NotNil(t, opts.randStringGenerator)

	opts.SetExtraDataGenerator(codegen.NewMockExtraDataGenerator(t).Execute)
	assert.NotNil(t, opts.extraDataGenerator)
}
