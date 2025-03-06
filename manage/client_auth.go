package manage

import (
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/models"
	"net/http"
)

type ClientAuthentication interface {
	Method() constants.TokenEndpointAuthMethodType
	Authenticate(r *http.Request) (models.Client, error)
}

type ClientBasicAuthentication struct {
	store ClientStore
}

func (h *ClientBasicAuthentication) Method() constants.TokenEndpointAuthMethodType {
	return constants.ClientSecretBasic
}

func (h *ClientBasicAuthentication) Authenticate(r *http.Request) (models.Client, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok || clientID == "" {
		return nil, ErrClientNotFound
	}

	client, err := h.store.FetchByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrUnauthorizedClient
	}

	return client, nil
}

type ClientFormAuthentication struct {
	store ClientStore
}

func (h *ClientFormAuthentication) Method() constants.TokenEndpointAuthMethodType {
	return constants.ClientSecretPost
}

func (h *ClientFormAuthentication) Authenticate(r *http.Request) (models.Client, error) {
	clientID := r.FormValue(constants.ParamClientID)
	if clientID == "" {
		return nil, ErrClientNotFound
	}

	client, err := h.store.FetchByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	clientSecret := r.FormValue(constants.ParamClientSecret)
	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrUnauthorizedClient
	}

	return client, nil
}

type ClientNoneAuthentication struct {
	store ClientStore
}

func (h *ClientNoneAuthentication) Method() constants.TokenEndpointAuthMethodType {
	return constants.None
}

func (h *ClientNoneAuthentication) Authenticate(r *http.Request) (models.Client, error) {
	clientID := r.FormValue(constants.ParamClientID)
	if clientID == "" {
		return nil, ErrClientNotFound
	}

	client, err := h.store.FetchByClientID(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	return client, nil
}
