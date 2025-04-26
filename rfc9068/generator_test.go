package rfc9068

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/tniah/authlib/integrations/sql"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"testing"
	"time"
)

func TestJWTAccessTokenGenerator(t *testing.T) {
	cfg := NewGeneratorConfig().
		SetIssuer("https://example.com").
		SetSigningKey([]byte("my-secret-key"), jwt.SigningMethodHS256, "my-kid-id").
		SetExpiresIn(time.Hour * 24)

	mockClient := &sql.Client{
		ClientID: uuid.NewString(),
		Scopes:   []string{"openid", "email", "profile"},
	}
	mockUser := &sql.User{
		UserID: uuid.NewString(),
	}
	mockToken := &sql.Token{}

	generator := NewJWTAccessTokenGenerator(cfg)
	r := &requests.TokenRequest{
		GrantType: "password",
		Client:    mockClient,
		User:      mockUser,
		Scopes:    types.NewScopes([]string{"openid", "email", "phoneNumber"}),
	}
	err := generator.Generate(mockToken, r)
	assert.NoError(t, err)
	assert.Equal(t, mockClient.ClientID, mockToken.GetClientID())
	assert.Equal(t, mockUser.GetUserID(), mockToken.GetUserID())
	assert.Contains(t, mockToken.GetScopes().String(), "openid")
	assert.Contains(t, mockToken.GetScopes().String(), "email")
	assert.NotContains(t, mockToken.GetScopes().String(), "phoneNumber")
	assert.Equal(t, false, mockToken.GetIssuedAt().IsZero())
	assert.Equal(t, cfg.expiresIn, mockToken.GetAccessTokenExpiresIn())
	assert.NotEmpty(t, mockToken.GetJwtID())
	assert.NotEmpty(t, mockToken.GetAccessToken())
}
