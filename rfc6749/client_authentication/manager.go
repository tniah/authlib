package clientauth

import (
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
	"net/http"
)

type Manager struct {
	handlers map[types.ClientAuthMethod]Handler
}

func NewManager() *Manager {
	return &Manager{
		handlers: make(map[types.ClientAuthMethod]Handler),
	}
}

func (m *Manager) Authenticate(r *http.Request, supportedMethods map[types.ClientAuthMethod]bool, endpoint string) (models.Client, error) {
	for method, ok := range supportedMethods {
		if !ok {
			continue
		}

		var h Handler
		if h, ok = m.handlers[method]; !ok {
			continue
		}

		client, err := h.Authenticate(r)
		if err != nil {
			continue
		}

		if client != nil && client.CheckTokenEndpointAuthMethod(method, endpoint) {
			return client, nil
		}
	}

	return nil, ErrInvalidClient
}

func (m *Manager) Register(h Handler) {
	if m.handlers == nil {
		m.handlers = make(map[types.ClientAuthMethod]Handler)
	}

	m.handlers[h.Method()] = h
}
