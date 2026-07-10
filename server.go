package authlib

import (
	"encoding/json"
	"fmt"
	"net/http"

	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/utils"
)

const (
	errCodeServerError         = "server_error"
	errDescInternalServerError = "An unexpected error occurred"
)

// Server is the central OAuth2 coordinator. It dispatches incoming HTTP
// requests to the appropriate grant flow or endpoint based on response_type
// or grant_type. Flows and endpoints must be registered before handling requests.
type Server struct {
	// Slices preserve registration order, ensuring deterministic dispatch
	// when iterating to find a matching grant/endpoint.
	authorizationGrants []AuthorizationGrant
	consentGrants       []ConsentGrant
	tokenGrants         []TokenGrant
	endpoints           []Endpoint
	// errHandler, if set, overrides the default OAuth2 error response logic.
	errHandler ErrorHandler
}

// NewServer creates an empty Server. Register grants and endpoints before use.
func NewServer() *Server {
	return &Server{}
}

// CreateAuthorizationRequest parses the HTTP request into an AuthorizationRequest.
func (srv *Server) CreateAuthorizationRequest(r *http.Request) (*requests.AuthorizationRequest, error) {
	return requests.NewAuthorizationRequestFromHttp(r)
}

// AuthorizationGrant returns the first registered grant that supports the
// requested response_type, or UnsupportedResponseTypeError if none match.
func (srv *Server) AuthorizationGrant(r *requests.AuthorizationRequest) (AuthorizationGrant, error) {
	for _, grant := range srv.authorizationGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedResponseTypeError()
}

// CreateAuthorizationResponse handles the /authorize endpoint. It parses the
// request, finds the matching grant, validates it, and writes the redirect response.
// u is the authenticated user; pass nil to trigger an access denied error.
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

// ConsentGrant returns the first registered grant that supports the consent
// step for the requested response_type.
func (srv *Server) ConsentGrant(r *requests.AuthorizationRequest) (ConsentGrant, error) {
	for _, grant := range srv.consentGrants {
		if grant.CheckResponseType(r.ResponseType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedResponseTypeError()
}

// CreateConsentResponse handles the consent page callback. It re-validates the
// authorization request after the user has approved (or denied) the consent screen.
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

// CreateTokenRequest parses the HTTP request into a TokenRequest.
func (srv *Server) CreateTokenRequest(r *http.Request) (*requests.TokenRequest, error) {
	return requests.NewTokenRequestFromHttp(r)
}

// TokenGrant returns the first registered grant that supports the requested
// grant_type, or UnsupportedGrantTypeError if none match.
func (srv *Server) TokenGrant(r *requests.TokenRequest) (TokenGrant, error) {
	for _, grant := range srv.tokenGrants {
		if grant.CheckGrantType(r.GrantType) {
			return grant, nil
		}
	}

	return nil, autherrors.UnsupportedGrantTypeError()
}

// CreateTokenResponse handles the /token endpoint. It parses the request,
// finds the matching grant, validates it, and writes the JSON token response.
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

// Endpoint returns the registered endpoint matching the given name, or an
// error if no endpoint is found.
func (srv *Server) Endpoint(name string) (Endpoint, error) {
	for _, endpoint := range srv.endpoints {
		if endpoint.CheckEndpoint(name) {
			return endpoint, nil
		}
	}

	return nil, fmt.Errorf("no endpoint was found with \"%s\"", name)
}

// EndpointResponse dispatches an HTTP request to a named endpoint (e.g. "introspect").
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

// RegisterGrant registers a grant flow for all applicable roles
// (AuthorizationGrant, ConsentGrant, TokenGrant) that it implements.
// A single flow struct may implement multiple interfaces simultaneously.
func (srv *Server) RegisterGrant(grant interface{}) {
	srv.RegisterAuthorizationGrant(grant)
	srv.RegisterConsentGrant(grant)
	srv.RegisterTokenGrant(grant)
}

// RegisterAuthorizationGrant registers grant as an AuthorizationGrant if it
// implements the interface. Grants are matched in registration order.
func (srv *Server) RegisterAuthorizationGrant(grant interface{}) {
	if g, ok := grant.(AuthorizationGrant); ok {
		srv.authorizationGrants = append(srv.authorizationGrants, g)
	}
}

// RegisterConsentGrant registers grant as a ConsentGrant if it implements
// the interface. Grants are matched in registration order.
func (srv *Server) RegisterConsentGrant(grant interface{}) {
	if g, ok := grant.(ConsentGrant); ok {
		srv.consentGrants = append(srv.consentGrants, g)
	}
}

// RegisterTokenGrant registers grant as a TokenGrant if it implements the
// interface. Grants are matched in registration order.
func (srv *Server) RegisterTokenGrant(grant interface{}) {
	if g, ok := grant.(TokenGrant); ok {
		srv.tokenGrants = append(srv.tokenGrants, g)
	}
}

// RegisterEndpoint registers an endpoint (e.g. token introspection) that can
// be dispatched to via EndpointResponse.
func (srv *Server) RegisterEndpoint(endpoint interface{}) {
	if g, ok := endpoint.(Endpoint); ok {
		srv.endpoints = append(srv.endpoints, g)
	}
}

// RegisterErrorHandler sets a custom error handler. When set, all errors are
// forwarded to h instead of the default OAuth2 JSON/redirect response logic.
func (srv *Server) RegisterErrorHandler(h ErrorHandler) {
	srv.errHandler = h
}

// HandleError converts err to an OAuth2 error response. If a custom
// ErrorHandler is registered it takes full control. Otherwise:
//   - If err carries a RedirectURI, the client is redirected with the error params.
//   - Otherwise a JSON error body is written with the appropriate HTTP status.
//
// Non-AuthLibError values (e.g. unexpected DB errors) are returned as-is; the
// caller is responsible for writing a 500 response in that case.
func (srv *Server) HandleError(hr *http.Request, rw http.ResponseWriter, err error) error {
	if !utils.IsNil(srv.errHandler) {
		return srv.errHandler(hr, rw, err)
	}

	authErr, err := autherrors.ToAuthLibError(err)
	if err != nil {
		// err is not an AuthLibError (e.g. unexpected internal error).
		// Return it to the caller without writing a response.
		return err
	}

	if authErr.RedirectURI != "" {
		return utils.Redirect(rw, authErr.RedirectURI, authErr.Data())
	}

	status, header, data := authErr.Response()
	return srv.JSONResponse(rw, status, header, data)
}

// JSONResponse writes a JSON-encoded response with the given status code and
// optional extra headers. It also sets Content-Type: application/json.
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
