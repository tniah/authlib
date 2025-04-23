package rfc6750

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tniah/authlib/mocks/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"testing"
	"time"
)

func TestOpaqueRefreshTokenGenerator(t *testing.T) {
	mockToken := models.NewMockToken(t)
	mockClient := models.NewMockClient(t)
	mockUser := models.NewMockUser(t)

	actual := &struct {
		refreshToken string
		expires      time.Duration
	}{}

	mockToken.On("SetRefreshTokenExpiresIn", mock.AnythingOfType("time.Duration")).Run(func(args mock.Arguments) {
		actual.expires = args.Get(0).(time.Duration)
	})

	mockToken.On("SetRefreshToken", mock.AnythingOfType("string")).Run(func(args mock.Arguments) {
		actual.refreshToken = args.Get(0).(string)
	})

	r := &requests.TokenRequest{
		GrantType: "password",
		Client:    mockClient,
		User:      mockUser,
		Scopes:    types.NewScopes([]string{"profile", "email"}),
	}
	g := NewOpaqueRefreshTokenGenerator()
	err := g.Generate(mockToken, r)
	assert.NoError(t, err)
	assert.Equal(t, DefaultTokenLength, len(actual.refreshToken))
	assert.Equal(t, DefaultRefreshTokenExpiresIn, actual.expires)

	mockToken.AssertExpectations(t)
	mockClient.AssertExpectations(t)
	mockUser.AssertExpectations(t)
}
