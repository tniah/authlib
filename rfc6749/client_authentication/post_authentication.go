package clientauth

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"net/http"
)

type PostAuthHandler struct {
	store ClientStore
}

func NewPostAuthHandler(store ClientStore) *PostAuthHandler {
	return &PostAuthHandler{store: store}
}

func (h *PostAuthHandler) Method() string {
	return AuthMethodClientSecretPost
}

func (h *PostAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
	if r.Method != http.MethodPost || !common.IsXWWWFormUrlencodedContentType(r) {
		return nil, ErrInvalidClient
	}

	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.store.FetchByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, ErrInvalidClient
	}

	clientSecret := r.PostFormValue("client_secret")
	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrInvalidClient
	}

	return client, nil
}
