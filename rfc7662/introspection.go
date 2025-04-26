package rfc7662

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/utils"
	"net/http"
	"time"
)

type TokenIntrospectionFlow struct {
	*Config
}

func NewTokenIntrospectionFlow(cfg *Config) *TokenIntrospectionFlow {
	return &TokenIntrospectionFlow{cfg}
}

func MustTokenIntrospectionFlow(cfg *Config) (*TokenIntrospectionFlow, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return NewTokenIntrospectionFlow(cfg), nil
}

func (f *TokenIntrospectionFlow) CheckEndpoint(name string) bool {
	if f.endpointName == "" {
		return false
	}

	return name == f.endpointName
}

func (f *TokenIntrospectionFlow) EndpointResponse(r *http.Request, rw http.ResponseWriter) error {
	client, err := f.clientManager.Authenticate(r, f.supportedClientAuthMethods, f.endpointName)
	if err != nil {
		return err
	}

	req := NewRequestFromHTTP(r)
	req.Client = client

	if err = f.authenticateToken(req); err != nil {
		return err
	}

	payload := f.introspectionPayload(req)
	return utils.JSONResponse(rw, payload, http.StatusOK)
}

func (f *TokenIntrospectionFlow) authenticateToken(r *Request) error {
	if err := f.checkParams(r); err != nil {
		return err
	}

	token, err := f.tokenManager.QueryByToken(r.Request.Context(), r.Token, r.TokenTypeHint)
	if err != nil {
		return err
	}

	if fn := f.clientManager.CheckPermission; fn != nil {
		if allowed := fn(r.Client, token, r.Request); !allowed {
			return autherrors.AccessDeniedError().WithDescription("client does not have permission to inspect token")
		}
	}

	r.Tok = token
	return nil
}

func (f *TokenIntrospectionFlow) checkParams(r *Request) error {
	if err := r.ValidateHTTPMethod(); err != nil {
		return err
	}

	if err := r.ValidateContentType(); err != nil {
		return err
	}

	if err := r.ValidateToken(); err != nil {
		return err
	}

	if err := r.ValidateTokenTypeHint(); err != nil {
		return err
	}

	return nil
}

func (f *TokenIntrospectionFlow) introspectionPayload(r *Request) map[string]interface{} {
	payload := map[string]interface{}{
		"active": false,
	}
	if r.Tok == nil {
		return payload
	}

	if r.Tok.GetIssuedAt().Add(r.Tok.GetAccessTokenExpiresIn()).Before(time.Now().UTC().Round(time.Second)) {
		return payload
	}

	if fn := f.tokenManager.Inspect; fn != nil {
		payload = fn(r.Client, r.Tok)
	}

	payload["active"] = true
	return payload
}
