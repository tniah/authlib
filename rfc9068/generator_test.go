package rfc9068

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tniah/authlib/mocks/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"testing"
	"time"
)

func TestJWTAccessTokenGenerator(t *testing.T) {
	mockClient := models.NewMockClient(t)
	mockUser := models.NewMockUser(t)
	mockToken := models.NewMockToken(t)

	cfg := NewGeneratorConfig().
		SetIssuer("https://example.com").
		SetSigningKey([]byte("my-secret-key"), jwt.SigningMethodHS256, "my-kid-id").
		SetExpiresIn(time.Hour * 24)

	actual := &struct {
		clientID    string
		userID      string
		scopes      []string
		issuedAt    time.Time
		expiresIn   time.Duration
		jwtID       string
		accessToken string
	}{}

	clientIDExpected := "my-client-id"
	mockClient.On("GetClientID").Return(clientIDExpected).Once()
	mockToken.On("SetClientID", mock.AnythingOfType("string")).Run(func(args mock.Arguments) {
		actual.clientID = args.Get(0).(string)
	})

	userIDExpected := "my-user-id"
	mockUser.On("GetUserID").Return(userIDExpected).Once()
	mockToken.On("SetUserID", mock.AnythingOfType("string")).Run(func(args mock.Arguments) {
		actual.userID = args.Get(0).(string)
	})

	scopesExpected := []string{"openid", "email", "profile"}
	mockClient.On("GetAllowedScopes", mock.AnythingOfType("[]string")).Return(scopesExpected).Once()
	mockToken.On("SetScopes", mock.AnythingOfType("[]string")).Run(func(args mock.Arguments) {
		actual.scopes = args.Get(0).([]string)
	})

	mockToken.On("SetIssuedAt", mock.AnythingOfType("time.Time")).Run(func(args mock.Arguments) {
		actual.issuedAt = args.Get(0).(time.Time)
	})

	mockToken.On("SetAccessTokenExpiresIn", mock.AnythingOfType("time.Duration")).Run(func(args mock.Arguments) {
		actual.expiresIn = args.Get(0).(time.Duration)
	})

	mockToken.On("GetJwtID").Return("").Once()
	mockToken.On("SetJwtID", mock.AnythingOfType("string")).Run(func(args mock.Arguments) {
		actual.jwtID = args.Get(0).(string)
	})

	mockToken.On("SetAccessToken", mock.AnythingOfType("string")).Run(func(args mock.Arguments) {
		actual.accessToken = args.Get(0).(string)
	})

	generator := NewJWTAccessTokenGenerator(cfg)
	r := &requests.TokenRequest{
		GrantType: "password",
		Client:    mockClient,
		User:      mockUser,
		Scopes:    types.NewScopes(scopesExpected),
	}
	err := generator.Generate(mockToken, r)
	assert.NoError(t, err)
	assert.Equal(t, clientIDExpected, actual.clientID)
	assert.Equal(t, userIDExpected, actual.userID)
	assert.Equal(t, scopesExpected, actual.scopes)
	assert.Equal(t, false, actual.issuedAt.IsZero())
	assert.Equal(t, cfg.expiresIn, actual.expiresIn)
	assert.NotEmpty(t, actual.jwtID)
	assert.NotEmpty(t, actual.accessToken)

	mockClient.AssertExpectations(t)
	mockUser.AssertExpectations(t)
	mockToken.AssertExpectations(t)
}
