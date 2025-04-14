package clientauth

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"net/http"
)

type NoneAuthHandler struct {
	*BaseHandler
}

func NewNoneAuthHandler(store ClientStore) *NoneAuthHandler {
	h := &NoneAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	h.SetClientStore(store)
	return h
}

func MustNoneAuthHandler(store ClientStore) (*NoneAuthHandler, error) {
	h := &NoneAuthHandler{
		BaseHandler: &BaseHandler{},
	}

	if err := h.MustClientStore(store); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *NoneAuthHandler) Method() string {
	return AuthMethodNone
}

func (h *NoneAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
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

	return client, nil
}
