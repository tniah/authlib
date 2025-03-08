package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/models"
)

var ErrInvalidUser = errors.New("invalid user")

type (
	UserManager struct {
		store UserStore
	}

	UserStore interface {
		FetchByID(ctx context.Context, id string) (models.User, error)
	}
)

func NewUserManager(store UserStore) *UserManager {
	return &UserManager{store: store}
}

func (m *UserManager) GetByID(ctx context.Context, userID string) (models.User, error) {
	u, err := m.store.FetchByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if u == nil {
		return nil, ErrInvalidUser
	}

	return u, nil
}
