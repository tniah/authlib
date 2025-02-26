package authlib

import (
	"encoding/json"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/rfc6749/errors"
	"github.com/tniah/authlib/rfc6749/request"
	"net/http"
)

type AuthorizationGrant interface {
	CheckResponseType(responseType string) bool
	ValidateRequest(r *request.AuthorizationRequest) error
	Response(rw http.ResponseWriter, r *request.AuthorizationRequest) error
}

type Server struct {
	authorizationGrants map[AuthorizationGrant]bool
}

func NewServer() *Server {
	return &Server{
		authorizationGrants: make(map[AuthorizationGrant]bool),
	}
}

func (srv *Server) CreateAuthorizationRequest(r *http.Request) *request.AuthorizationRequest {
	//TODO
	return &request.AuthorizationRequest{
		ClientID:     r.FormValue("client_id"),
		ResponseType: r.FormValue("response_type"),
		RedirectURI:  r.FormValue("redirect_uri"),
		State:        r.FormValue("state"),
		Request:      r,
	}
}

func (srv *Server) GetAuthorizationGrant(r *request.AuthorizationRequest) (AuthorizationGrant, error) {
	for grant := range srv.authorizationGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}

	return nil, errors.NewUnsupportedResponseTypeError()
}

func (srv *Server) HandleError(rw http.ResponseWriter, err error) error {
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

func (srv *Server) JSONResponse(rw http.ResponseWriter, status int, header http.Header, data map[string]interface{}) error {
	rw.Header().Set(headerContentType, contentTypeJSON)
	rw.Header().Set(headerCacheControl, cacheControlNoStore)
	rw.Header().Set(headerPragma, pragmaNoCache)

	for k := range header {
		rw.Header().Set(k, header.Get(k))
	}

	rw.WriteHeader(status)
	return json.NewEncoder(rw).Encode(data)
}
