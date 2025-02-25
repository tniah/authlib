package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/oauth2/rfc6749/grants"
	"net/http"
)

var ErrClientNotFound = errors.New("client not found")

type ClientStore interface {
	FetchByClientId(ctx context.Context, id string) (grants.OAuthClient, error)
}

type ClientManager struct {
	store ClientStore
}

func NewClientManager(store ClientStore) *ClientManager {
	return &ClientManager{store: store}
}

func (m *ClientManager) QueryByClientId(ctx context.Context, ClientID string) (grants.OAuthClient, error) {
	client, err := m.store.FetchByClientId(ctx, ClientID)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, ErrClientNotFound
	}

	return client, nil
}

func (m *ClientManager) Authenticate(r *http.Request) (grants.OAuthClient, error) {
	return nil, nil
}
