package manage

import (
	"errors"
	"github.com/tniah/authlib/oauth2/rfc6749/models"
	"net/http"
)

var ErrClientNotFound = errors.New("client not found")

type ClientStore interface {
	FetchByClientId(id string) (models.OAuthClient, error)
}

type ClientManager struct {
	store ClientStore
}

func NewClientManager(store ClientStore) *ClientManager {
	return &ClientManager{store: store}
}

func (m *ClientManager) QueryByClientID(ClientID string) (models.OAuthClient, error) {
	client, err := m.store.FetchByClientId(ClientID)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, ErrClientNotFound
	}

	return client, nil
}

func (m *ClientManager) Authenticate(r *http.Request) (models.OAuthClient, error) {
	return nil, nil
}
