package rfc6750

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/tniah/authlib/integrations/sql"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"testing"
)

func TestOpaqueAccessTokenGenerator(t *testing.T) {
	mockClient := &sql.Client{
		ClientID: uuid.NewString(),
		Scopes:   []string{"openid", "email", "profile"},
	}
	mockToken := &sql.Token{}
	mockUser := &sql.User{
		UserID: uuid.NewString(),
	}
	r := &requests.TokenRequest{
		GrantType: "password",
		Client:    mockClient,
		User:      mockUser,
		Scopes:    types.NewScopes([]string{"openid", "email", "test"}),
	}

	g := NewOpaqueAccessTokenGenerator()
	err := g.Generate(mockToken, r)
	assert.NoError(t, err)
	assert.Equal(t, mockClient.GetClientID(), mockToken.GetClientID())
	assert.Equal(t, mockUser.GetUserID(), mockToken.GetUserID())
	assert.Contains(t, mockToken.Scopes, "openid")
	assert.Contains(t, mockToken.Scopes, "email")
	assert.NotContains(t, mockToken.Scopes, "test")
	assert.False(t, mockToken.GetIssuedAt().IsZero())
	assert.Equal(t, DefaultExpiresIn, mockToken.GetAccessTokenExpiresIn())
	assert.Equal(t, DefaultTokenLength, len(mockToken.GetAccessToken()))
}
