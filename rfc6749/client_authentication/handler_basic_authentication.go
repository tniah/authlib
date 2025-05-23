package clientauth

import (
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
	"net/http"
)

type BasicAuthHandler struct {
	*BaseHandler
}

func NewBasicAuthHandler(store ClientStore) *BasicAuthHandler {
	h := &BasicAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	h.SetClientStore(store)
	return h
}

func MustBasicAuthHandler(store ClientStore) (*BasicAuthHandler, error) {
	h := &BasicAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	if err := h.MustClientStore(store); err != nil {
		return nil, err
	}

	return h, nil
}

func (h *BasicAuthHandler) Method() types.ClientAuthMethod {
	return types.ClientBasicAuthentication
}

func (h *BasicAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok || clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.store.QueryByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, ErrInvalidClient
	}

	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrInvalidClient
	}

	return client, nil
}
