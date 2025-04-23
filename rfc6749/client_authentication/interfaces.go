package clientauth

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
	"net/http"
)

type ClientStore interface {
	QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
}

type Handler interface {
	Method() types.ClientAuthMethod
	Authenticate(r *http.Request) (models.Client, error)
}
