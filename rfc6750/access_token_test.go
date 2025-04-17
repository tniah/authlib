package rfc6750

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tniah/authlib/mocks/models"
	"github.com/tniah/authlib/requests"
	"testing"
	"time"
)

func TestOpaqueAccessTokenGenerator(t *testing.T) {
	mockToken := models.NewMockToken(t)
	mockClient := models.NewMockClient(t)
	mockUser := models.NewMockUser(t)

	actual := &struct {
		clientID    string
		userID      string
		scopes      []string
		issuedAt    time.Time
		expiresIn   time.Duration
		accessToken string
	}{}

	expectedClientID := "my-client-id"
	mockClient.On("GetClientID").Return(expectedClientID).Once()
	mockToken.On("SetClientID", mock.AnythingOfType("string")).Run(func(args mock.Arguments) {
		actual.clientID = args.Get(0).(string)
	})

	expectedUserID := "my-user-id"
	mockUser.On("GetSubjectID").Return(expectedUserID).Once()
	mockToken.On("SetUserID", mock.AnythingOfType("string")).Run(func(args mock.Arguments) {
		actual.userID = args.Get(0).(string)
	})

	expectedScopes := []string{"openid", "email", "profile"}
	mockClient.On("GetAllowedScopes", mock.AnythingOfType("[]string")).Return(expectedScopes).Once()
	mockToken.On("SetScopes", mock.AnythingOfType("[]string")).Run(func(args mock.Arguments) {
		actual.scopes = args.Get(0).([]string)
	})

	mockToken.On("SetIssuedAt", mock.AnythingOfType("time.Time")).Run(func(args mock.Arguments) {
		actual.issuedAt = args.Get(0).(time.Time)
	})

	mockToken.On("SetAccessTokenExpiresIn", mock.AnythingOfType("time.Duration")).Run(func(args mock.Arguments) {
		actual.expiresIn = args.Get(0).(time.Duration)
	})

	mockToken.On("SetAccessToken", mock.AnythingOfType("string")).Run(func(args mock.Arguments) {
		actual.accessToken = args.Get(0).(string)
	})

	r := &requests.TokenRequest{
		GrantType: "password",
		Client:    mockClient,
		User:      mockUser,
		Scopes:    expectedScopes,
	}

	g := NewOpaqueAccessTokenGenerator()
	err := g.Generate(mockToken, r)
	assert.NoError(t, err)
	assert.Equal(t, expectedClientID, actual.clientID)
	assert.Equal(t, expectedUserID, actual.userID)
	assert.Equal(t, expectedScopes, actual.scopes)
	assert.NotEqual(t, time.Time{}, actual.issuedAt)
	assert.Equal(t, DefaultExpiresIn, actual.expiresIn)
	assert.Equal(t, DefaultTokenLength, len(actual.accessToken))
}
