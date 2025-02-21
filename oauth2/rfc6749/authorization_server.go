package rfc6749

import (
	"net/http"
)

type AuthorizationServer interface {
	QueryClient(ClientID string) OAuthClient
	CreateAuthorizationRequest(r *http.Request) *AuthorizationRequest
	CreateAuthorizationResponse(rw http.ResponseWriter, r *AuthorizationRequest) error
	//CreateTokenRequest(r *http.Request)
	//CreateTokenResponse(rw http.ResponseWriter, r *http.Request)
}

type DefaultAuthorizationServer struct {
	authorizationGrants map[AuthorizationRequestHandler]bool
}

func NewAuthorizationServer() AuthorizationServer {
	return nil
}

func (srv *DefaultAuthorizationServer) QueryClient(clientID string) OAuthClient {
	return nil
}

func (srv *DefaultAuthorizationServer) CreateAuthorizationRequest(r *http.Request) *AuthorizationRequest {
	return &AuthorizationRequest{
		ClientID:     r.FormValue("client_id"),
		ResponseType: ResponseType(r.FormValue("response_type")),
		RedirectURI:  r.FormValue("redirect_uri"),
		Scope:        r.FormValue("scope"),
		State:        r.FormValue("state"),
		Request:      r,
	}
}

func (srv *DefaultAuthorizationServer) GetAuthorizationRequestHandler(r *AuthorizationRequest) (AuthorizationRequestHandler, error) {
	for grant := range srv.authorizationGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}
	return nil, NewUnsupportedResponseTypeError()
}

func (srv *DefaultAuthorizationServer) CreateAuthorizationResponse(rw http.ResponseWriter, r *AuthorizationRequest) error {
	return nil
}

func (srv *DefaultAuthorizationServer) RegisterGrant(grant interface{}) {
	g, ok := grant.(OAuth2Grant)
	if !ok {
		return
	}
	g.RegisterWithServer(srv)

	switch t := grant.(type) {
	case AuthorizationRequestHandler:
		srv.authorizationGrants[t] = true
	default:
		return
	}
}
