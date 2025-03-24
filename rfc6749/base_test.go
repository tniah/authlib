package rfc6749

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/mocks/models"
	"github.com/tniah/authlib/requests"
	"testing"
)

func TestValidateRedirectURI(t *testing.T) {
	c := models.NewMockClient(t)
	r := &requests.AuthorizationRequest{
		State: uuid.NewString(),
	}

	g := AuthorizationGrantMixin{}
	var authErr *errors.AuthLibError
	for _, v := range []struct {
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
	} {
		r.RedirectURI = v.RedirectURI
		if r.RedirectURI == "" {
			c.EXPECT().GetDefaultRedirectURI().Return(v.DefaultRedirectURI).Once()
		} else {
			c.EXPECT().CheckRedirectURI(r.RedirectURI).Return(false).Once()
		}

		actual, err := g.ValidateRedirectURI(r, c)
		assert.ErrorAs(t, err, &authErr)
		assert.Empty(t, actual)
		assert.Equal(t, authErr.State, r.State)
		assert.Equal(t, authErr.Description, v.ErrDescription)
	}

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
		assert.NoError(t, err, "error = %v", err)
		assert.Equal(t, v.Expected, actual, "expected = %v, actual = %v", v.Expected, actual)
	}
}
