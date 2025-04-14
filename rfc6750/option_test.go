package rfc6750

import (
	"github.com/stretchr/testify/assert"
	"github.com/tniah/authlib/mocks/rfc6750"
	"testing"
	"time"
)

func TestBearerTokenGeneratorOptions(t *testing.T) {
	opts := NewBearerTokenGeneratorOptions()
	opts.SetAccessTokenGenerator(rfc6750.NewMockTokenGenerator(t))
	opts.SetRefreshTokenGenerator(rfc6750.NewMockTokenGenerator(t))
	assert.NotNil(t, opts.atGen)
	assert.NotNil(t, opts.rfGen)

	opts.SetAccessTokenGenerator(nil)
	err := opts.Validate()
	assert.ErrorIs(t, err, ErrNilAccessTokenGenerator)

	opts.SetAccessTokenGenerator(rfc6750.NewMockTokenGenerator(t))
	opts.SetRefreshTokenGenerator(nil)
	err = opts.Validate()
	assert.ErrorIs(t, err, ErrNilRefreshTokenGenerator)
}

func TestTokenGeneratorOptions(t *testing.T) {
	opts := NewTokenGeneratorOptions()
	expected := &TokenGeneratorOptions{
		tokenLength:         12,
		expiresIn:           time.Second * 60,
		expiresInGenerator:  rfc6750.NewMockExpiresInGenerator(t).Execute,
		randStringGenerator: rfc6750.NewMockRandStringGenerator(t).Execute,
	}

	opts.SetTokenLength(expected.tokenLength)
	opts.SetExpiresIn(expected.expiresIn)
	opts.SetExpiresInGenerator(expected.expiresInGenerator)
	opts.SetRandStringGenerator(expected.randStringGenerator)

	assert.Equal(t, expected.tokenLength, opts.tokenLength)
	assert.Equal(t, expected.expiresIn, opts.expiresIn)
	assert.NotNil(t, opts.expiresInGenerator)
	assert.NotNil(t, opts.randStringGenerator)
}
