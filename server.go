package authlib

import (
	"encoding/json"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/requests"
	"net/http"
)

type AuthorizationGrant interface {
	CheckResponseType(responseType string) bool
	ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error
	AuthorizationResponse(rw http.ResponseWriter, r *requests.AuthorizationRequest) error
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
		ResponseType:        r.FormValue(constants.QueryParamResponseType),
		ClientID:            r.FormValue(constants.QueryParamClientID),
		RedirectURI:         r.FormValue(constants.QueryParamRedirectURI),
		Scope:               r.FormValue(constants.QueryParamScope),
		State:               r.FormValue(constants.QueryParamState),
		Nonce:               r.FormValue(constants.QueryParamNonce),
		CodeChallenge:       r.FormValue(constants.QueryParamCodeChallenge),
		CodeChallengeMethod: r.FormValue(constants.QueryParamCodeChallengeMethod),
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
