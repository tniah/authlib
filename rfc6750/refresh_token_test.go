package rfc6750

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tniah/authlib/integrations/sql"
	"github.com/tniah/authlib/requests"
)

func TestOpaqueRefreshTokenGenerator(t *testing.T) {
	mockToken := &sql.Token{}
	r := &requests.TokenRequest{
		GrantType: "password",
	}
	g := NewOpaqueRefreshTokenGenerator()
	err := g.Generate(mockToken, r)
	assert.NoError(t, err)
	assert.Equal(t, DefaultTokenLength, len(mockToken.GetRefreshToken()))
	assert.Equal(t, DefaultRefreshTokenExpiresIn, mockToken.GetRefreshTokenExpiresIn())
}
