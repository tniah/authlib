package clientauth

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"net/http"
)

type PostAuthHandler struct {
	*BaseHandler
}

func NewPostAuthHandler(store ClientStore) *PostAuthHandler {
	h := &PostAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	h.SetClientStore(store)
	return h
}

func MustPostAuthHandler(store ClientStore) (*PostAuthHandler, error) {
	h := &PostAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	if err := h.MustClientStore(store); err != nil {
		return nil, err
	}

	return h, nil
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

	client, err := h.store.QueryByClientID(r.Context(), clientID)
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
