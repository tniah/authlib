package manage

import (
	"errors"
	"github.com/tniah/authlib/oauth2/rfc6749"
	"net/http"
)

var ErrClientNotFound = errors.New("client not found")

type ClientStore interface {
	QueryClientByID(id string) (rfc6749.OAuthClient, error)
}

type ClientManager struct {
	store ClientStore
}

func NewClientManager(store ClientStore) *ClientManager {
	return &ClientManager{store: store}
}

func (m *ClientManager) QueryByClientID(ClientID string) (rfc6749.OAuthClient, error) {
	client, err := m.store.QueryClientByID(ClientID)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, ErrClientNotFound
	}

	return client, nil
}

func (m *ClientManager) Authenticate(r *http.Request) (rfc6749.OAuthClient, error) {
	return nil, nil
}
