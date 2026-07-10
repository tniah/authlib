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

const (
	errCodeServerError         = "server_error"
	errDescInternalServerError = "An unexpected error occurred"
)

type Server struct {
	authorizationGrants []AuthorizationGrant
	consentGrants       []ConsentGrant
	tokenGrants         []TokenGrant
	endpoints           []Endpoint
	errHandler          ErrorHandler
}

func NewServer() *Server {
	return &Server{}
}

func (srv *Server) CreateAuthorizationRequest(r *http.Request) (*requests.AuthorizationRequest, error) {
	return requests.NewAuthorizationRequestFromHttp(r)
}

func (srv *Server) AuthorizationGrant(r *requests.AuthorizationRequest) (AuthorizationGrant, error) {
	for _, grant := range srv.authorizationGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedResponseTypeError()
}

func (srv *Server) CreateAuthorizationResponse(hr *http.Request, rw http.ResponseWriter, u models.User) error {
	r, err := srv.CreateAuthorizationRequest(hr)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	r.User = u
	grant, err := srv.AuthorizationGrant(r)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = grant.ValidateAuthorizationRequest(r); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = grant.AuthorizationResponse(r, rw); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	return nil
}

func (srv *Server) ConsentGrant(r *requests.AuthorizationRequest) (ConsentGrant, error) {
	for _, grant := range srv.consentGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedResponseTypeError()
}

func (srv *Server) CreateConsentResponse(hr *http.Request, rw http.ResponseWriter, u models.User) error {
	r, err := srv.CreateAuthorizationRequest(hr)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	r.User = u
	grant, err := srv.ConsentGrant(r)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = grant.ValidateConsentRequest(r); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = grant.AuthorizationResponse(r, rw); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	return nil
}

func (srv *Server) CreateTokenRequest(r *http.Request) (*requests.TokenRequest, error) {
	return requests.NewTokenRequestFromHttp(r)
}

func (srv *Server) TokenGrant(r *requests.TokenRequest) (TokenGrant, error) {
	for _, grant := range srv.tokenGrants {
		if grant.CheckGrantType(r.GrantType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedGrantTypeError()
}

func (srv *Server) CreateTokenResponse(hr *http.Request, rw http.ResponseWriter) error {
	r, err := srv.CreateTokenRequest(hr)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	grant, err := srv.TokenGrant(r)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = grant.ValidateTokenRequest(r); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = grant.TokenResponse(r, rw); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	return nil
}

func (srv *Server) Endpoint(name string) (Endpoint, error) {
	for _, endpoint := range srv.endpoints {
		if endpoint.CheckEndpoint(name) {
			return endpoint, nil
		}
	}

	return nil, fmt.Errorf("no endpoint was found with \"%s\"", name)
}

func (srv *Server) EndpointResponse(hr *http.Request, rw http.ResponseWriter, name string) error {
	h, err := srv.Endpoint(name)
	if err != nil {
		return srv.HandleError(hr, rw, err)
	}

	if err = h.EndpointResponse(hr, rw); err != nil {
		return srv.HandleError(hr, rw, err)
	}

	return nil
}

func (srv *Server) RegisterGrant(grant interface{}) {
	srv.RegisterAuthorizationGrant(grant)
	srv.RegisterConsentGrant(grant)
	srv.RegisterTokenGrant(grant)
}

func (srv *Server) RegisterAuthorizationGrant(grant interface{}) {
	if g, ok := grant.(AuthorizationGrant); ok {
		srv.authorizationGrants = append(srv.authorizationGrants, g)
	}
}

func (srv *Server) RegisterConsentGrant(grant interface{}) {
	if g, ok := grant.(ConsentGrant); ok {
		srv.consentGrants = append(srv.consentGrants, g)
	}
}

func (srv *Server) RegisterTokenGrant(grant interface{}) {
	if g, ok := grant.(TokenGrant); ok {
		srv.tokenGrants = append(srv.tokenGrants, g)
	}
}

func (srv *Server) RegisterEndpoint(endpoint interface{}) {
	if g, ok := endpoint.(Endpoint); ok {
		srv.endpoints = append(srv.endpoints, g)
	}
}

func (srv *Server) RegisterErrorHandler(h ErrorHandler) {
	srv.errHandler = h
}

func (srv *Server) HandleError(hr *http.Request, rw http.ResponseWriter, err error) error {
	if !utils.IsNil(srv.errHandler) {
		return srv.errHandler(hr, rw, err)
	}

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
