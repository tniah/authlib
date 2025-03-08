package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/models"
	"net/http"
)

var ErrInvalidClient = errors.New("invalid client")

type ClientStore interface {
	FetchByClientID(ctx context.Context, clientID string) (models.Client, error)
}

type ClientManager struct {
	store       ClientStore
	authMethods map[ClientAuthentication]bool
}

func NewClientManager(store ClientStore) *ClientManager {
	return &ClientManager{
		store:       store,
		authMethods: make(map[ClientAuthentication]bool),
	}
}

func (m *ClientManager) QueryByClientID(ctx context.Context, clientID string) (models.Client, error) {
	client, err := m.store.FetchByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, ErrInvalidClient
	}

	return client, nil
}

func (m *ClientManager) Authenticate(r *http.Request) (models.Client, string, error) {
	for h, _ := range m.authMethods {
		client, err := h.Authenticate(r)
		if err == nil && client.CheckTokenEndpointAuthMethod(h.Method()) {
			return client, h.Method(), nil
		}
	}

	return nil, "", ErrInvalidClient
}

func (m *ClientManager) RegisterAuthMethod(authMethod ClientAuthentication) {
	if m.authMethods == nil {
		m.authMethods = make(map[ClientAuthentication]bool)
	}

	m.authMethods[authMethod] = true
}
