package authlib

import (
	"encoding/json"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/requests"
	"net/http"
	"strings"
)

const (
	ParamCode                = "code"
	ParamResponseType        = "response_type"
	ParamRedirectURI         = "redirect_uri"
	ParamScope               = "scope"
	ParamState               = "state"
	ParamNonce               = "nonce"
	ParamCodeChallenge       = "code_challenge"
	ParamCodeChallengeMethod = "code_challenge_method"
	ParamClientID            = "client_id"
	ParamGrantType           = "grant_type"
	ParamUsername            = "username"
	ParamPassword            = "password"
)

type (
	Server struct {
		authorizationGrants map[AuthorizationGrant]bool
		tokenGrants         map[TokenGrant]bool
	}

	AuthorizationGrant interface {
		CheckResponseType(responseType string) bool
		ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error
		AuthorizationResponse(rw http.ResponseWriter, r *requests.AuthorizationRequest) error
	}

	TokenGrant interface {
		CheckGrantType(grantType string) bool
		ValidateTokenRequest(r *requests.TokenRequest) error
		TokenResponse(rw http.ResponseWriter, r *requests.TokenRequest) error
	}
)

func NewServer() *Server {
	return &Server{
		authorizationGrants: make(map[AuthorizationGrant]bool),
		tokenGrants:         make(map[TokenGrant]bool),
	}
}

func (srv *Server) CreateAuthorizationRequest(r *http.Request) *requests.AuthorizationRequest {
	return &requests.AuthorizationRequest{
		ResponseType:        r.FormValue(ParamResponseType),
		ClientID:            r.FormValue(ParamClientID),
		RedirectURI:         r.FormValue(ParamRedirectURI),
		Scopes:              strings.Fields(r.FormValue(ParamScope)),
		State:               r.FormValue(ParamState),
		Nonce:               r.FormValue(ParamNonce),
		CodeChallenge:       r.FormValue(ParamCodeChallenge),
		CodeChallengeMethod: r.FormValue(ParamCodeChallengeMethod),
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

func (srv *Server) CreateTokenRequest(r *http.Request) *requests.TokenRequest {
	return &requests.TokenRequest{
		GrantType:   r.FormValue(ParamGrantType),
		ClientID:    r.FormValue(ParamClientID),
		Code:        r.FormValue(ParamCode),
		RedirectURI: r.FormValue(ParamRedirectURI),
		Scopes:      strings.Fields(r.FormValue(ParamScope)),
		Username:    r.FormValue(ParamUsername),
		Password:    r.FormValue(ParamPassword),
		Request:     r,
	}
}

func (srv *Server) GetTokenGrant(r *requests.TokenRequest) (TokenGrant, error) {
	for grant := range srv.tokenGrants {
		if grant.CheckGrantType(r.GrantType) {
			return grant, nil
		}
	}

	return nil, errors.NewUnsupportedGrantTypeError()
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

	switch t := grant.(type) {
	case TokenGrant:
		if srv.tokenGrants == nil {
			srv.tokenGrants = make(map[TokenGrant]bool)
		}
		srv.tokenGrants[t] = true
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
