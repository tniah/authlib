package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/models"
)

var ErrClientNotFound = errors.New("client not found")

type ClientStore interface {
	FetchByClientID(ctx context.Context, clientID string) (models.Client, error)
}

type ClientManager struct {
	store ClientStore
}

func NewClientManager(store ClientStore) *ClientManager {
	return &ClientManager{store: store}
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
