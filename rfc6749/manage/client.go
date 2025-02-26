package manage

import (
	"errors"
	"github.com/tniah/authlib/rfc6749/model"
)

var ErrClientNotFound = errors.New("client not found")

type ClientStore interface {
	FetchByClientID(clientID string) (model.Client, error)
}

type ClientManager struct {
	store ClientStore
}

func (m *ClientManager) QueryByClientID(clientID string) (model.Client, error) {
	c, err := m.store.FetchByClientID(clientID)
	if err != nil {
		return nil, err
	}

	if c == nil {
		return nil, ErrClientNotFound
	}

	return c, nil
}
