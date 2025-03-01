package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/models"
)

var ErrUserNotFound = errors.New("user not found")

type UserStore interface {
	FetchByID(ctx context.Context, id string) (models.User, error)
}

type UserManager struct {
	store UserStore
}

func NewUserManager(store UserStore) *UserManager {
	return &UserManager{store: store}
}

func (m *UserManager) GetByID(ctx context.Context, id string) (models.User, error) {
	u, err := m.store.FetchByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if u == nil {
		return nil, ErrUserNotFound
	}

	return u, nil
}
