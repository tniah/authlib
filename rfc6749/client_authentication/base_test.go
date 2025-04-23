package clientauth

import (
	"github.com/stretchr/testify/assert"
	rfc6749 "github.com/tniah/authlib/mocks/rfc6749/client_authentication"
	"testing"
)

func TestBaseHandler(t *testing.T) {
	h := BaseHandler{}
	t.Run("success", func(t *testing.T) {
		store := rfc6749.NewMockClientStore(t)
		h.SetClientStore(store)
		assert.NotNil(t, h.store)
	})

	t.Run("error", func(t *testing.T) {
		err := h.MustClientStore(nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNilClientStore)
	})
}
