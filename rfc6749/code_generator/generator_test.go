package codegen

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tniah/authlib/integrations/sql"
	codegen "github.com/tniah/authlib/mocks/rfc6749/code_generator"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"testing"
	"time"
)

func TestGenerator_New(t *testing.T) {
	g := New(NewOptions().SetExpiresIn(time.Hour * 24).SetCodeLength(128))
	assert.Equal(t, time.Hour*24, g.expiresIn)
	assert.Equal(t, 128, g.codeLength)

	g = New()
	assert.Equal(t, DefaultExpiresIn, g.expiresIn)
	assert.Equal(t, DefaultCodeLength, g.codeLength)
}

func TestGenerator_Generate(t *testing.T) {
	mockClient := &sql.Client{
		ClientID: uuid.NewString(),
	}
	mockUser := &sql.User{
		UserID: uuid.NewString(),
	}
	r := &requests.AuthorizationRequest{
		GrantType:    types.GrantTypeAuthorizationCode,
		RedirectURI:  "http://example.com",
		ResponseType: types.ResponseTypeCode,
		Scopes:       types.NewScopes([]string{"profile", "openid"}),
		State:        uuid.NewString(),
		Client:       mockClient,
		User:         mockUser,
	}
	mockAuthCode := &sql.AuthorizationCode{}
	extraDataGen := codegen.NewMockExtraDataGenerator(t)
	extraData := map[string]interface{}{
		"session_id": uuid.NewString(),
	}
	extraDataGen.EXPECT().Execute(mock.AnythingOfType("*requests.AuthorizationRequest")).Return(extraData, nil).Once()

	g := New(NewOptions().SetExtraDataGenerator(extraDataGen.Execute))
	err := g.Generate(mockAuthCode, r)
	assert.NoError(t, err)
	assert.Equal(t, DefaultCodeLength, len(mockAuthCode.GetCode()))
	assert.Equal(t, mockClient.GetClientID(), mockAuthCode.GetClientID())
	assert.Equal(t, mockUser.GetUserID(), mockAuthCode.GetUserID())
	assert.Equal(t, r.RedirectURI, mockAuthCode.GetRedirectURI())
	assert.Equal(t, r.ResponseType, mockAuthCode.GetResponseType())
	assert.Equal(t, r.Scopes, mockAuthCode.GetScopes())
	assert.Equal(t, r.State, mockAuthCode.GetState())
	assert.False(t, mockAuthCode.GetAuthTime().IsZero())
	assert.Equal(t, DefaultExpiresIn, mockAuthCode.GetExpiresIn())
	assert.Equal(t, extraData, mockAuthCode.GetExtraData())
}

func TestGenerator_genCode(t *testing.T) {
	strGen := codegen.NewMockRandStringGenerator(t)
	expected := "thisIsARandomString"
	strGen.EXPECT().Execute(mock.AnythingOfType("types.GrantType"), mock.AnythingOfType("*sql.Client")).Return(expected).Once()

	mockClient := &sql.Client{}
	g := New(NewOptions().SetRandStringGenerator(strGen.Execute))
	s := g.genCode(types.GrantTypeAuthorizationCode, mockClient)
	assert.Equal(t, expected, s)

	g.SetRandStringGenerator(nil)
	s = g.genCode(types.GrantTypeAuthorizationCode, mockClient)
	assert.Equal(t, DefaultCodeLength, len(s))
}

func TestGenerator_expiresInHandler(t *testing.T) {
	expInGen := codegen.NewMockExpiresInGenerator(t)
	expected := 10 * time.Minute
	expInGen.EXPECT().Execute(mock.AnythingOfType("types.GrantType"), mock.AnythingOfType("*sql.Client")).Return(expected).Once()

	mockClient := &sql.Client{}
	g := New(NewOptions().SetExpiresInGenerator(expInGen.Execute))
	exp := g.expiresInHandler(types.GrantTypeAuthorizationCode, mockClient)
	assert.Equal(t, expected, exp)

	expected = 30 * time.Minute
	g.SetExpiresInGenerator(nil)
	g.SetExpiresIn(expected)
	exp = g.expiresInHandler(types.GrantTypeAuthorizationCode, mockClient)
	assert.Equal(t, expected, exp)
}
