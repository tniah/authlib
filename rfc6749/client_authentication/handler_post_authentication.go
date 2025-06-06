package clientauth

import (
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
	"github.com/tniah/authlib/utils"
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

func (h *PostAuthHandler) Method() types.ClientAuthMethod {
	return types.ClientPostAuthentication
}

func (h *PostAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
	if r.Method != http.MethodPost {
		return nil, ErrInvalidClient
	}

	ct, err := utils.ContentType(r)
	if err != nil {
		return nil, ErrInvalidClient
	}

	if valid := ct.IsXWWWFormUrlencoded(); !valid {
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
