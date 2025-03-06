package manage

import (
	"context"
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/models"
	"net/http"
	"sync"
)

type ClientStore interface {
	FetchByClientID(ctx context.Context, clientID string) (models.Client, error)
}

type ClientManager struct {
	lock               *sync.Mutex
	store              ClientStore
	authMethods        map[ClientAuthentication]bool
	defaultAuthMethods map[ClientAuthentication]bool
}

func NewClientManager(store ClientStore) *ClientManager {
	return &ClientManager{
		lock:  &sync.Mutex{},
		store: store,
	}
}

func (m *ClientManager) QueryByClientID(ctx context.Context, clientID string) (models.Client, error) {
	c, err := m.store.FetchByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	if c == nil {
		return nil, ErrClientNotFound
	}

	return c, nil
}

func (m *ClientManager) Authenticate(r *http.Request) (models.Client, constants.TokenEndpointAuthMethodType, error) {
	authMethods := m.authMethods
	if authMethods == nil {
		authMethods = m.DefaultAuthMethods()
	}

	for h, _ := range authMethods {
		client, err := h.Authenticate(r)
		if err == nil {
			return client, h.Method(), nil
		}
	}

	return nil, "", ErrUnauthorizedClient
}

func (m *ClientManager) RegisterAuthMethod(authMethod ClientAuthentication) {
	if m.authMethods == nil {
		m.authMethods = make(map[ClientAuthentication]bool)
	}

	m.authMethods[authMethod] = true
}

func (m *ClientManager) DefaultAuthMethods() map[ClientAuthentication]bool {
	if m.defaultAuthMethods == nil {
		m.lock.Lock()
		defer m.lock.Unlock()

		if m.defaultAuthMethods == nil {
			noneAuth := &ClientNoneAuthentication{store: m.store}
			basicAuth := &ClientBasicAuthentication{store: m.store}
			formAuth := &ClientFormAuthentication{store: m.store}
			m.defaultAuthMethods = map[ClientAuthentication]bool{
				noneAuth:  true,
				basicAuth: true,
				formAuth:  true,
			}
		}
	}

	return m.defaultAuthMethods
}
