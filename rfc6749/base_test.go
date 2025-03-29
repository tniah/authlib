package rfc6749

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/mocks/models"
	"github.com/tniah/authlib/requests"
	"strings"
	"testing"
	"time"
)

func TestValidateRedirectURI(t *testing.T) {
	g := AuthorizationGrantMixin{}
	c := models.NewMockClient(t)
	r := &requests.AuthorizationRequest{
		State: uuid.NewString(),
	}

	t.Run("error", func(t *testing.T) {
		cases := []struct {
			RedirectURI        string
			DefaultRedirectURI string
			ErrDescription     string
		}{
			{
				RedirectURI:        "",
				DefaultRedirectURI: "",
				ErrDescription:     ErrMissingRedirectURI,
			},
			{
				RedirectURI:        "http://example.com",
				DefaultRedirectURI: "http://example.com",
				ErrDescription:     ErrUnsupportedRedirectURI,
			},
		}

		var authErr *errors.AuthLibError
		for _, v := range cases {
			r.RedirectURI = v.RedirectURI
			if r.RedirectURI == "" {
				c.EXPECT().GetDefaultRedirectURI().Return(v.DefaultRedirectURI).Once()
			} else {
				c.EXPECT().CheckRedirectURI(r.RedirectURI).Return(false).Once()
			}

			actual, err := g.ValidateRedirectURI(r, c)
			assert.ErrorAs(t, err, &authErr)
			assert.Emptyf(t, actual, "expected=\"\", actual=%s", actual)
			assert.Equalf(t, r.State, authErr.State, "expected=%s, actual=%s", r.State, authErr.State)
			assert.Equalf(t, v.ErrDescription, authErr.Description, "expected=%s, actual=%s", v.ErrDescription, actual)
		}
	})

	for _, v := range []struct {
		RedirectURI        string
		DefaultRedirectURI string
		Expected           string
	}{
		{
			RedirectURI:        "",
			DefaultRedirectURI: "http://example.com",
			Expected:           "http://example.com",
		},
		{
			RedirectURI:        "http://example.com",
			DefaultRedirectURI: "http://makai.com",
			Expected:           "http://example.com",
		},
	} {
		r.RedirectURI = v.RedirectURI
		if r.RedirectURI == "" {
			c.EXPECT().GetDefaultRedirectURI().Return(v.DefaultRedirectURI).Once()
		} else {
			c.EXPECT().CheckRedirectURI(r.RedirectURI).Return(true).Once()
		}

		actual, err := g.ValidateRedirectURI(r, c)
		assert.NoErrorf(t, err, "error = %v", err)
		assert.Equalf(t, v.Expected, actual, "expected = %v, actual = %v", v.Expected, actual)
	}
}

func TestStandardTokenData(t *testing.T) {
	token := models.NewMockToken(t)
	tokenType := "Bearer"
	accessToken := uuid.NewString()
	refreshToken := uuid.NewString()
	expiresIn := time.Minute * 60
	scopes := []string{"openid", "email"}

	token.EXPECT().GetType().Return(tokenType).Once()
	token.EXPECT().GetAccessToken().Return(accessToken).Once()
	token.EXPECT().GetRefreshToken().Return(refreshToken).Once()
	token.EXPECT().GetScopes().Return(scopes).Once()
	token.EXPECT().GetAccessTokenExpiresIn().Return(expiresIn).Once()

	g := TokenGrantMixin{}
	data := g.StandardTokenData(token)
	assert.Equalf(t, tokenType, data[ParamTokeType], "token type: expected=%s, actual=%s", tokenType, data[ParamTokeType])
	assert.Equalf(t, accessToken, data[ParamAccessToken], "access token: expected=%s, actual=%s", accessToken, data[ParamAccessToken])
	assert.Equalf(t, expiresIn.Seconds(), data[ParamExpiresIn], "expires in: expected=%f, actual=%f", expiresIn.Seconds(), data[ParamExpiresIn])
	assert.Equalf(t, refreshToken, data[ParamRefreshToken], "refresh token: expected=%s, actual=%s", refreshToken, data[ParamRefreshToken])
	assert.Equalf(t, strings.Join(scopes, " "), data[ParamScope], "scope: expected=%s, actual=%s", strings.Join(scopes, " "), data[ParamScope])
}
