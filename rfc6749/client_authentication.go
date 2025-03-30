package rfc6749

import (
	"errors"
	"github.com/tniah/authlib/models"
	"mime"
	"net/http"
)

var ErrInvalidClient = errors.New("invalid client")

type ClientAuthHandler interface {
	Method() string
	Authenticate(r *http.Request) (models.Client, error)
}

type ClientAuthenticationManager struct {
	authHandlers map[ClientAuthHandler]bool
}

func (m *ClientAuthenticationManager) Authenticate(r *http.Request) (models.Client, error) {
	for h, _ := range m.authHandlers {
		client, err := h.Authenticate(r)
		if err == nil && client.CheckTokenEndpointAuthMethod(h.Method()) {
			return client, nil
		}
	}

	return nil, ErrInvalidClient
}

func (m *ClientAuthenticationManager) RegisterAuthHandler(h ClientAuthHandler) {
	if m.authHandlers == nil {
		m.authHandlers = make(map[ClientAuthHandler]bool)
	}

	m.authHandlers[h] = true
}

type ClientBasicAuthHandler struct {
	queryClient QueryClient
}

func (h *ClientBasicAuthHandler) Method() string {
	return AuthMethodClientSecretBasic
}

func (h *ClientBasicAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok || clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.queryClient(r.Context(), clientID)
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

type ClientNoneAuthHandler struct {
	queryClient QueryClient
}

func (h *ClientNoneAuthHandler) Method() string {
	return AuthMethodNone
}

func (h *ClientNoneAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
	clientID := r.FormValue(ParamClientID)
	if clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.queryClient(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, ErrInvalidClient
	}

	return client, nil
}

type ClientPostAuthHandler struct {
	queryClient QueryClient
}

func (h *ClientPostAuthHandler) Method() string {
	return AuthMethodClientSecretPost
}

func (h *ClientPostAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
	if r.Method != http.MethodPost {
		return nil, ErrInvalidClient
	}

	ct, _, err := mime.ParseMediaType(r.Header.Get(HeaderContentType))
	if err != nil {
		return nil, err
	}

	if ct != ContentTypeXWwwFormUrlEncoded {
		return nil, ErrInvalidClient
	}

	clientID := r.PostFormValue(ParamClientID)
	if clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.queryClient(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, ErrInvalidClient
	}

	clientSecret := r.PostFormValue(ParamClientSecret)
	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrInvalidClient
	}

	return client, nil
}
