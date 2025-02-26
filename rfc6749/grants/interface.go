package grants

import (
	"github.com/tniah/authlib/rfc6749/model"
	"github.com/tniah/authlib/rfc6749/request"
)

type ClientManager interface {
	QueryByClientID(clientID string) (model.Client, error)
}

type AuthorizationCodeManager interface {
	Generate(grantType string, r *request.AuthorizationRequest) (string, error)
}
