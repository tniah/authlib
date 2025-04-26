package rfc6750

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tniah/authlib/integrations/sql"
	"github.com/tniah/authlib/mocks/rfc6750"
	"github.com/tniah/authlib/requests"
	"testing"
)

func TestTestBearerTokenGenerator(t *testing.T) {
	g := NewBearerTokenGenerator()
	atGenerator := rfc6750.NewMockTokenGenerator(t)
	atGenerator.On(
		"Generate",
		mock.AnythingOfType("*sql.Token"),
		mock.AnythingOfType("*requests.TokenRequest"),
	).Return(nil).Once()
	g.SetAccessTokenGenerator(atGenerator)

	rtGenerator := rfc6750.NewMockTokenGenerator(t)
	rtGenerator.On(
		"Generate",
		mock.AnythingOfType("*sql.Token"),
		mock.AnythingOfType("*requests.TokenRequest"),
	).Return(nil).Once()
	g.SetRefreshTokenGenerator(rtGenerator)

	mockToken := &sql.Token{}
	r := &requests.TokenRequest{
		GrantType: "password",
	}
	err := g.Generate(mockToken, r, true)
	assert.NoError(t, err)
	assert.Equal(t, TokenTypeBearer, mockToken.GetType())
}
