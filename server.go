package authlib

import (
	"encoding/json"
	"fmt"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/utils"
	"net/http"
)

type Server struct {
	authorizationGrants map[AuthorizationGrant]bool
	consentGrants       map[ConsentGrant]bool
	tokenGrants         map[TokenGrant]bool
	endpoints           map[Endpoint]bool
}

func NewServer() *Server {
	return &Server{
		authorizationGrants: make(map[AuthorizationGrant]bool),
		consentGrants:       make(map[ConsentGrant]bool),
		tokenGrants:         make(map[TokenGrant]bool),
	}
}

func (srv *Server) CreateAuthorizationRequest(r *http.Request) (*requests.AuthorizationRequest, error) {
	return requests.NewAuthorizationRequestFromHttp(r)
}

func (srv *Server) GetAuthorizationGrant(r *requests.AuthorizationRequest) (AuthorizationGrant, error) {
	for grant := range srv.authorizationGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedResponseTypeError()
}

func (srv *Server) GetConsentGrant(r *requests.AuthorizationRequest) (ConsentGrant, error) {
	for grant := range srv.consentGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedResponseTypeError()
}

func (srv *Server) CreateAuthorizationResponse(hr *http.Request, rw http.ResponseWriter, u models.User) error {
	r, err := srv.CreateAuthorizationRequest(hr)
	if err != nil {
		return srv.HandleError(rw, err)
	}

	r.User = u
	grant, err := srv.GetAuthorizationGrant(r)
	if err != nil {
		return srv.HandleError(rw, err)
	}

	if err := grant.ValidateAuthorizationRequest(r); err != nil {
		return srv.HandleError(rw, err)
	}

	if err := grant.AuthorizationResponse(r, rw); err != nil {
		return srv.HandleError(rw, err)
	}

	return nil
}

func (srv *Server) CreateConsentResponse(hr *http.Request, rw http.ResponseWriter, u models.User) error {
	r, err := srv.CreateAuthorizationRequest(hr)
	if err != nil {
		return srv.HandleError(rw, err)
	}

	r.User = u
	grant, err := srv.GetConsentGrant(r)
	if err != nil {
		return srv.HandleError(rw, err)
	}

	if err := grant.ValidateConsentRequest(r); err != nil {
		return srv.HandleError(rw, err)
	}

	if err := grant.AuthorizationResponse(r, rw); err != nil {
		return srv.HandleError(rw, err)
	}

	return nil
}

func (srv *Server) CreateTokenRequest(r *http.Request) (*requests.TokenRequest, error) {
	return requests.NewTokenRequestFromHttp(r)
}

func (srv *Server) GetTokenGrant(r *requests.TokenRequest) (TokenGrant, error) {
	for grant := range srv.tokenGrants {
		if grant.CheckGrantType(r.GrantType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedGrantTypeError()
}

func (srv *Server) Endpoint(name string) (Endpoint, error) {
	for endpoint := range srv.endpoints {
		if endpoint.CheckEndpoint(name) {
			return endpoint, nil
		}
	}

	return nil, fmt.Errorf("no endpoint was found with \"%s\"", name)
}

func (srv *Server) RegisterGrant(grant interface{}) {
	srv.RegisterAuthorizationGrant(grant)
	srv.RegisterConsentGrant(grant)
	srv.RegisterTokenGrant(grant)
}

func (srv *Server) RegisterAuthorizationGrant(grant interface{}) {
	if g, ok := grant.(AuthorizationGrant); ok {
		if srv.authorizationGrants == nil {
			srv.authorizationGrants = make(map[AuthorizationGrant]bool)
		}

		srv.authorizationGrants[g] = true
	}
}

func (srv *Server) RegisterConsentGrant(grant interface{}) {
	if g, ok := grant.(ConsentGrant); ok {
		if srv.consentGrants == nil {
			srv.consentGrants = make(map[ConsentGrant]bool)
		}

		srv.consentGrants[g] = true
	}
}

func (srv *Server) RegisterTokenGrant(grant interface{}) {
	if g, ok := grant.(TokenGrant); ok {
		if srv.tokenGrants == nil {
			srv.tokenGrants = make(map[TokenGrant]bool)
		}
		srv.tokenGrants[g] = true
	}
}

func (srv *Server) RegisterEndpoint(endpoint interface{}) {
	if g, ok := endpoint.(Endpoint); ok {
		if srv.endpoints == nil {
			srv.endpoints = make(map[Endpoint]bool)
		}

		srv.endpoints[g] = true
	}
}

func (srv *Server) HandleError(rw http.ResponseWriter, err error) error {
	authErr, err := autherrors.ToAuthLibError(err)
	if err != nil {
		return err
	}

	if authErr.RedirectURI != "" {
		return utils.Redirect(rw, authErr.RedirectURI, authErr.Data())
	}

	status, header, data := authErr.Response()
	return srv.JSONResponse(rw, status, header, data)
}

func (srv *Server) JSONResponse(rw http.ResponseWriter, status int, header http.Header, data map[string]interface{}) error {
	for k, v := range utils.JSONHeaders() {
		rw.Header().Set(k, v)
	}

	for k := range header {
		rw.Header().Set(k, header.Get(k))
	}

	rw.WriteHeader(status)
	return json.NewEncoder(rw).Encode(data)
}
