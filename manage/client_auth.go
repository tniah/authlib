package manage

import (
	"github.com/tniah/authlib/models"
	"net/http"
)

const (
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodNone              = "none"
	ParamClientID               = "client_id"
	ParamClientSecret           = "client_secret"
)

type ClientAuthentication interface {
	Method() string
	Authenticate(r *http.Request) (models.Client, error)
}

type ClientBasicAuthentication struct {
	store ClientStore
}

func NewClientBasicAuthentication(store ClientStore) *ClientBasicAuthentication {
	return &ClientBasicAuthentication{store: store}
}

func (h *ClientBasicAuthentication) Method() string {
	return AuthMethodClientSecretBasic
}

func (h *ClientBasicAuthentication) Authenticate(r *http.Request) (models.Client, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok || clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.store.FetchByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrInvalidClient
	}

	return client, nil
}

type ClientFormAuthentication struct {
	store ClientStore
}

func NewClientFormAuthentication(store ClientStore) *ClientFormAuthentication {
	return &ClientFormAuthentication{store: store}
}

func (h *ClientFormAuthentication) Method() string {
	return AuthMethodClientSecretPost
}

func (h *ClientFormAuthentication) Authenticate(r *http.Request) (models.Client, error) {
	clientID := r.FormValue(ParamClientID)
	if clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.store.FetchByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	clientSecret := r.FormValue(ParamClientSecret)
	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrInvalidClient
	}

	return client, nil
}

type ClientNoneAuthentication struct {
	store ClientStore
}

func NewClientNoneAuthentication(store ClientStore) *ClientNoneAuthentication {
	return &ClientNoneAuthentication{store: store}
}

func (h *ClientNoneAuthentication) Method() string {
	return AuthMethodNone
}

func (h *ClientNoneAuthentication) Authenticate(r *http.Request) (models.Client, error) {
	clientID := r.FormValue(ParamClientID)
	if clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.store.FetchByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	return client, nil
}
