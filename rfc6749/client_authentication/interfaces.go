package clientauth

import (
	"context"
	"github.com/tniah/authlib/models"
	"net/http"
)

type ClientStore interface {
	QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
}

type Handler interface {
	Method() string
	Authenticate(r *http.Request) (models.Client, error)
}
