package authlib

import (
	"encoding/json"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/requests"
	"net/http"
)

const (
	QueryParamResponseType        = "response_type"
	QueryParamClientID            = "client_id"
	QueryParamRedirectURI         = "redirect_uri"
	QueryParamScope               = "scope"
	QueryParamState               = "state"
	QueryParamNonce               = "nonce"
	QueryParamCodeChallenge       = "code_challenge"
	QueryParamCodeChallengeMethod = "code_challenge_method"
)

type AuthorizationGrant interface {
	CheckResponseType(responseType string) bool
	ValidateRequest(r *requests.AuthorizationRequest) error
	Response(rw http.ResponseWriter, r *requests.AuthorizationRequest) error
}

type Server struct {
	authorizationGrants map[AuthorizationGrant]bool
}

func NewServer() *Server {
	return &Server{
		authorizationGrants: make(map[AuthorizationGrant]bool),
	}
}

func (srv *Server) CreateAuthorizationRequest(r *http.Request) *requests.AuthorizationRequest {
	return &requests.AuthorizationRequest{
		ResponseType:        r.FormValue(QueryParamResponseType),
		ClientID:            r.FormValue(QueryParamClientID),
		RedirectURI:         r.FormValue(QueryParamRedirectURI),
		Scope:               r.FormValue(QueryParamScope),
		State:               r.FormValue(QueryParamState),
		Nonce:               r.FormValue(QueryParamNonce),
		CodeChallenge:       r.FormValue(QueryParamCodeChallenge),
		CodeChallengeMethod: r.FormValue(QueryParamCodeChallengeMethod),
		Request:             r,
	}
}

func (srv *Server) GetAuthorizationGrant(r *requests.AuthorizationRequest) (AuthorizationGrant, error) {
	for grant := range srv.authorizationGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}
	return nil, errors.NewUnsupportedResponseTypeError()
}

func (srv *Server) RegisterGrant(grant interface{}) {
	switch t := grant.(type) {
	case AuthorizationGrant:
		if srv.authorizationGrants == nil {
			srv.authorizationGrants = make(map[AuthorizationGrant]bool)
		}
		srv.authorizationGrants[t] = true
	default:
		return
	}
}

func (srv *Server) HandleError(rw http.ResponseWriter, err error) error {
	authErr, err := errors.ToAuthLibError(err)
	if err != nil {
		return err
	}

	if authErr.RedirectURI != "" {
		return common.Redirect(rw, authErr.RedirectURI, authErr.Data())
	}

	status, header, data := authErr.Response()
	return srv.JSONResponse(rw, status, header, data)
}

func (srv *Server) JSONResponse(rw http.ResponseWriter, status int, header http.Header, data map[string]interface{}) error {
	for k, v := range common.DefaultJSONHeader() {
		rw.Header().Set(k, v)
	}

	for k := range header {
		rw.Header().Set(k, header.Get(k))
	}

	rw.WriteHeader(status)
	return json.NewEncoder(rw).Encode(data)
}
