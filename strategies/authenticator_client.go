package strategies

import (
	"context"
	"errors"
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

var ErrInvalidClient = errors.New("invalid client")

type QueryClient func(ctx context.Context, clientID string) (models.Client, error)

type ClientAuthHandler interface {
	Method() string
	Authenticate(r *http.Request) (models.Client, error)
}

type ClientBasicAuthHandler struct {
	queryClient QueryClient
}

func NewClientBasicAuthHandler(queryClient QueryClient) *ClientBasicAuthHandler {
	return &ClientBasicAuthHandler{queryClient: queryClient}
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

	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrInvalidClient
	}

	return client, nil
}

type ClientFormAuthHandler struct {
	queryClient QueryClient
}

func NewClientFormAuthHandler(queryClient QueryClient) *ClientFormAuthHandler {
	return &ClientFormAuthHandler{queryClient: queryClient}
}

func (h *ClientFormAuthHandler) Method() string {
	return AuthMethodClientSecretPost
}

func (h *ClientFormAuthHandler) Authenticate(r *http.Request) (models.Client, error) {
	clientID := r.FormValue(ParamClientID)
	if clientID == "" {
		return nil, ErrInvalidClient
	}

	client, err := h.queryClient(r.Context(), clientID)
	if err != nil {
		return nil, err
	}

	clientSecret := r.FormValue(ParamClientSecret)
	if !client.CheckClientSecret(clientSecret) {
		return nil, ErrInvalidClient
	}

	return client, nil
}

type ClientNoneAuthHandler struct {
	queryClient QueryClient
}

func NewClientNoneAuthHandler(queryClient QueryClient) *ClientNoneAuthHandler {
	return &ClientNoneAuthHandler{queryClient: queryClient}
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

	return client, nil
}

type ClientAuthenticator struct {
	queryClient  QueryClient
	authHandlers map[ClientAuthHandler]bool
}

func NewClientAuthenticator(queryClient QueryClient) *ClientAuthenticator {
	return &ClientAuthenticator{
		queryClient:  queryClient,
		authHandlers: make(map[ClientAuthHandler]bool),
	}
}

func (m *ClientAuthenticator) Authenticate(r *http.Request) (models.Client, string, error) {
	for h, _ := range m.authHandlers {
		client, err := h.Authenticate(r)
		if err == nil && client.CheckTokenEndpointAuthMethod(h.Method()) {
			return client, h.Method(), nil
		}
	}

	return nil, "", ErrInvalidClient
}

func (m *ClientAuthenticator) RegisterAuthMethod(authMethod ClientAuthHandler) {
	if m.authHandlers == nil {
		m.authHandlers = make(map[ClientAuthHandler]bool)
	}

	m.authHandlers[authMethod] = true
}
