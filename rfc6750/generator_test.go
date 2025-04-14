package rfc6750

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tniah/authlib/mocks/models"
	"github.com/tniah/authlib/mocks/rfc6750"
	"testing"
)

func TestTestBearerTokenGenerator(t *testing.T) {
	g := NewBearerTokenGenerator()
	atGenerator := rfc6750.NewMockTokenGenerator(t)
	atGenerator.On(
		"Generate",
		mock.AnythingOfType("string"),
		mock.AnythingOfType("*models.MockToken"),
		mock.AnythingOfType("*models.MockClient"),
		mock.AnythingOfType("*models.MockUser"),
		mock.AnythingOfType("[]string"),
	).Return(nil).Once()
	g.SetAccessTokenGenerator(atGenerator)

	rtGenerator := rfc6750.NewMockTokenGenerator(t)
	rtGenerator.On(
		"Generate",
		mock.AnythingOfType("string"),
		mock.AnythingOfType("*models.MockToken"),
		mock.AnythingOfType("*models.MockClient"),
		mock.AnythingOfType("*models.MockUser"),
		mock.AnythingOfType("[]string"),
	).Return(nil).Once()
	g.SetRefreshTokenGenerator(rtGenerator)

	mockToken := models.NewMockToken(t)
	mockClient := models.NewMockClient(t)
	mockUser := models.NewMockUser(t)
	scopes := []string{"openid", "profile"}
	actual := &struct {
		tokenType string
	}{}
	mockToken.On("SetType", mock.AnythingOfType("string")).Run(func(args mock.Arguments) {
		actual.tokenType = args.Get(0).(string)
	})

	err := g.Generate("password", mockToken, mockClient, mockUser, scopes, true)
	assert.NoError(t, err)
	assert.Equal(t, TokenTypeBearer, actual.tokenType)
}
