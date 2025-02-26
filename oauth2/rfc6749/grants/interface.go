package grants

import (
	"context"
	"net/http"
)

type AuthorizationGrant interface {
	CheckResponseType(responseType string) bool
	ValidateRequest(r AuthorizationRequest) error
	Response(rw http.ResponseWriter, r AuthorizationRequest) error
}

type AuthorizationRequest interface {
	ResponseType() string
	ClientID() string
	RedirectURI() string
	SetRedirectURI(uri string)
	Scopes() []string
	State() string
	UserID() string
	Client() OAuthClient
	SetClient(client OAuthClient)
	Request() *http.Request
}

type ClientManager interface {
	QueryByClientID(ctx context.Context, ClientID string) (OAuthClient, error)
}

type AuthorizationCodeManager interface {
	Generate(gt GrantType, r AuthorizationRequest) (AuthorizationCode, error)
}
