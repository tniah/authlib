package clientauth

import (
	"github.com/tniah/authlib/models"
	"net/http"
)

type BasicAuthHandler struct {
	*BaseHandler
}

func NewBasicAuthHandler() *BasicAuthHandler {
	return &BasicAuthHandler{
		BaseHandler: &BaseHandler{},
	}
}

func MustBasicAuthHandler(store ClientStore) (*BasicAuthHandler, error) {
	h := NewBasicAuthHandler()
	if err := h.MustClientStore(store); err != nil {
		return nil, err
	}

	return h, nil
}

func (h *BasicAuthHandler) Method() string {
	return AuthMethodClientSecretBasic
}

func (h *BasicAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok || clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.store.FetchByClientID(r.Context(), clientID)
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
