package clientauth

import (
	"context"
	"net/http"

	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
)

type ClientStore interface {
	QueryByClientID(ctx context.Context, clientID string) (models.Client, error)
}

type Handler interface {
	Method() types.ClientAuthMethod
	Authenticate(r *http.Request) (models.Client, error)
}
