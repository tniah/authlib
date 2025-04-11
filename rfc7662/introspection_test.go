package rfc7662

import (
	"github.com/stretchr/testify/assert"
	autherrors "github.com/tniah/authlib/errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTokenIntrospection(t *testing.T) {

}

func TestCheckEndpoint(t *testing.T) {
	cfg := NewIntrospectionConfig().SetEndpointName(EndpointNameTokenIntrospection)
	h := NewTokenIntrospection(cfg)
	cases := []struct {
		name     string
		expected bool
	}{
		{
			"my-endpoint",
			false,
		},
		{
			EndpointNameTokenIntrospection,
			true,
		},
	}
	for i, test := range cases {
		ret := h.CheckEndpoint(test.name)
		assert.Equalf(t, test.expected, ret, "case %d failed", i)
	}
}

func TestCheckParams(t *testing.T) {
	h := NewTokenIntrospection(NewIntrospectionConfig())

	t.Run("success", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
		r.Header.Set(HeaderContentType, ContentTypeXWwwFormUrlEncoded)

		err := h.checkParams(r)
		assert.NoError(t, err)
	})

	t.Run("error_when_http_method_is_disallowed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		err := h.checkParams(r)
		authErr, err := autherrors.ToAuthLibError(err)
		assert.NoError(t, err)
		assert.Equal(t, ErrRequestMustBePost, authErr.Description)
	})

	t.Run("error_when_content_type_is_invalid", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=access_token"))
		err := h.checkParams(r)
		authErr, err := autherrors.ToAuthLibError(err)
		assert.NoError(t, err)
		assert.Equal(t, autherrors.ErrInvalidRequest, authErr.Code)
	})

	t.Run("error_when_media_type_is_not_supported", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{\"token\":\"my-token\"}"))
		r.Header.Set(HeaderContentType, "application/json")
		err := h.checkParams(r)
		authErr, err := autherrors.ToAuthLibError(err)
		assert.NoError(t, err)
		assert.Equal(t, ErrInvalidContentType, authErr.Description)
	})

	t.Run("error_when_token_hint_is_invalid", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=my-token&token_type_hint=my-hint"))
		r.Header.Set(HeaderContentType, ContentTypeXWwwFormUrlEncoded)

		err := h.checkParams(r)
		authErr, err := autherrors.ToAuthLibError(err)
		assert.NoError(t, err)
		assert.Equal(t, ErrInvalidTokenTypeHint, authErr.Description)
	})
}
