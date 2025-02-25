package rfc6749

import (
	"encoding/json"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/oauth2/rfc6749/errors"
	"github.com/tniah/authlib/oauth2/rfc6749/grants"
	"net/http"
)

type AuthorizationServer interface {
	CreateAuthorizationRequest(r *http.Request) *grants.AuthorizationRequest
	GetAuthorizationGrant(r *grants.AuthorizationRequest) (grants.AuthorizationGrant, error)
	RegisterGrant(grant interface{})
	HandleError(rw http.ResponseWriter, err error) error
}

type DefaultAuthorizationServer struct {
	authorizationGrants map[grants.AuthorizationGrant]bool
}

func NewAuthorizationServer() AuthorizationServer {
	return &DefaultAuthorizationServer{
		authorizationGrants: make(map[grants.AuthorizationGrant]bool),
	}
}

func (srv *DefaultAuthorizationServer) CreateAuthorizationRequest(r *http.Request) *grants.AuthorizationRequest {
	return &grants.AuthorizationRequest{
		ClientID:     r.FormValue("client_id"),
		ResponseType: grants.ResponseType(r.FormValue("response_type")),
		RedirectURI:  r.FormValue("redirect_uri"),
		Scope:        r.FormValue("scope"),
		State:        r.FormValue("state"),
		Request:      r,
	}
}

func (srv *DefaultAuthorizationServer) GetAuthorizationGrant(r *grants.AuthorizationRequest) (grants.AuthorizationGrant, error) {
	for grant := range srv.authorizationGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}
	return nil, errors.NewUnsupportedResponseTypeError()
}

func (srv *DefaultAuthorizationServer) CreateAuthorizationResponse(rw http.ResponseWriter, req *http.Request) error {
	r := srv.CreateAuthorizationRequest(req)
	grant, err := srv.GetAuthorizationGrant(r)
	if err != nil {
		return srv.HandleError(rw, err)
	}

	if err = grant.ValidateRequest(r); err != nil {
		return srv.HandleError(rw, err)
	}

	if err = grant.Response(rw, r); err != nil {
		return srv.HandleError(rw, err)
	}

	return nil
}

func (srv *DefaultAuthorizationServer) RegisterGrant(grant interface{}) {
	//g, ok := grant.(OAuth2Grant)
	//if !ok {
	//	return
	//}
	//g.RegisterWithServer(srv)

	switch t := grant.(type) {
	case grants.AuthorizationGrant:
		if srv.authorizationGrants == nil {
			srv.authorizationGrants = make(map[grants.AuthorizationGrant]bool)
		}
		srv.authorizationGrants[t] = true
	default:
		return
	}
}

func (srv *DefaultAuthorizationServer) HandleError(rw http.ResponseWriter, err error) error {
	authErr, err := errors.ToOAuth2Error(err)
	if err != nil {
		return err
	}

	if authErr.RedirectUri != "" {
		return common.Redirect(rw, authErr.RedirectUri, authErr.Data())
	}

	status, header, data := authErr.Response()
	return srv.JSONResponse(rw, status, header, data)
}

func (srv *DefaultAuthorizationServer) JSONResponse(rw http.ResponseWriter, status int, header http.Header, data map[string]interface{}) error {
	rw.Header().Set(headerContentType, contentTypeJSON)
	rw.Header().Set(headerCacheControl, cacheControlNoStore)
	rw.Header().Set(headerPragma, pragmaNoCache)

	for k := range header {
		rw.Header().Set(k, header.Get(k))
	}

	rw.WriteHeader(status)
	return json.NewEncoder(rw).Encode(data)
}
