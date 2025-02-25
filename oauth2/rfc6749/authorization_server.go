package rfc6749

import (
	"encoding/json"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/oauth2/rfc6749/errors"
	"github.com/tniah/authlib/oauth2/rfc6749/grants"
	"net/http"
)

const (
	headerLocation      = "Location"
	headerContentType   = "Content-Type"
	headerCacheControl  = "Cache-Control"
	headerPragma        = "Pragma"
	contentTypeJSON     = "application/json;charset=UTF-8"
	cacheControlNoStore = "no-store"
	pragmaNoCache       = "no-cache"
)

type AuthorizationServer struct {
	authorizationGrants map[grants.AuthorizationGrant]bool
}

func NewAuthorizationServer() *AuthorizationServer {
	return &AuthorizationServer{}
}

func (srv *AuthorizationServer) CreateAuthorizationRequest(r *http.Request) *grants.AuthorizationRequest {
	return &grants.AuthorizationRequest{
		ClientID:     r.FormValue("client_id"),
		ResponseType: grants.ResponseType(r.FormValue("response_type")),
		RedirectURI:  r.FormValue("redirect_uri"),
		Scope:        r.FormValue("scope"),
		State:        r.FormValue("state"),
		Request:      r,
	}
}

func (srv *AuthorizationServer) GetAuthorizationGrant(r *grants.AuthorizationRequest) (grants.AuthorizationGrant, error) {
	for grant := range srv.authorizationGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}
	return nil, errors.NewUnsupportedResponseTypeError()
}

func (srv *AuthorizationServer) CreateAuthorizationResponse(rw http.ResponseWriter, req *http.Request) error {
	r := srv.CreateAuthorizationRequest(req)
	grant, err := srv.GetAuthorizationGrant(r)
	if err != nil {
		return srv.HandleOAuth2Error(rw, err)
	}

	if err = grant.ValidateRequest(r); err != nil {
		return srv.HandleOAuth2Error(rw, err)
	}

	if err = grant.Response(rw, r); err != nil {
		return srv.HandleOAuth2Error(rw, err)
	}

	return nil
}

func (srv *AuthorizationServer) RegisterGrant(grant interface{}) {
	//g, ok := grant.(OAuth2Grant)
	//if !ok {
	//	return
	//}
	//g.RegisterWithServer(srv)

	switch t := grant.(type) {
	case grants.AuthorizationGrant:
		srv.authorizationGrants[t] = true
	default:
		return
	}
}

func (srv *AuthorizationServer) HandleOAuth2Error(rw http.ResponseWriter, err error) error {
	authErr, err := errors.ToOAuth2Error(err)
	if err != nil {
		return err
	}

	if authErr.RedirectUri != "" {
		return common.Redirect(rw, authErr.RedirectUri, authErr.Data())
	}

	status, header, data := authErr.Response()
	return srv.HandleJSONResponse(rw, status, header, data)
}

func (srv *AuthorizationServer) HandleJSONResponse(rw http.ResponseWriter, status int, header http.Header, data map[string]interface{}) error {
	rw.Header().Set(headerContentType, contentTypeJSON)
	rw.Header().Set(headerCacheControl, cacheControlNoStore)
	rw.Header().Set(headerPragma, pragmaNoCache)

	for k := range header {
		rw.Header().Set(k, header.Get(k))
	}

	rw.WriteHeader(status)
	return json.NewEncoder(rw).Encode(data)
}
