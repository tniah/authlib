package clientauth

import (
	"github.com/tniah/authlib/models"
	"net/http"
)

type BasicAuthHandler struct {
	store ClientStore
}

func NewBasicAuthHandler(store ClientStore) *BasicAuthHandler {
	return &BasicAuthHandler{store: store}
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
