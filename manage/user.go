package manage

import (
	"context"
	"github.com/tniah/authlib/models"
)

type UserStore interface {
	FetchByID(ctx context.Context, id string) (models.User, error)
}

type UserManager struct {
	store UserStore
}

func NewUserManager(store UserStore) *UserManager {
	return &UserManager{store: store}
}

func (m *UserManager) GetByID(ctx context.Context, userID string) (models.User, error) {
	return m.store.FetchByID(ctx, userID)
}
