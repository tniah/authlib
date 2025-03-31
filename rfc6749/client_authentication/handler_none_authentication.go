package clientauth

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"net/http"
)

type NoneAuthHandler struct {
	store ClientStore
}

func NewNoneAuthHandler(store ClientStore) *NoneAuthHandler {
	return &NoneAuthHandler{store: store}
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
