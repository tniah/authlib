package rfc7662

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/utils"
	"net/http"
	"time"
)

type TokenIntrospection struct {
	*IntrospectionConfig
}

func NewTokenIntrospection(cfg *IntrospectionConfig) *TokenIntrospection {
	return &TokenIntrospection{cfg}
}

func MustTokenIntrospection(cfg *IntrospectionConfig) (*TokenIntrospection, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return NewTokenIntrospection(cfg), nil
}

func (t *TokenIntrospection) CheckEndpoint(name string) bool {
	if t.endpointName == "" {
		return false
	}

	return name == t.endpointName
}

func (t *TokenIntrospection) EndpointResponse(r *http.Request, rw http.ResponseWriter) error {
	client, err := t.clientManager.Authenticate(r, t.clientAuthMethods, t.endpointName)
	if err != nil {
		return err
	}

	req := NewIntrospectionRequestFromHTTP(r)
	req.Client = client

	if err = t.authenticateToken(req); err != nil {
		return err
	}

	payload := t.introspectionPayload(req)
	return utils.JSONResponse(rw, payload, http.StatusOK)
}

func (t *TokenIntrospection) authenticateToken(r *IntrospectionRequest) error {
	if err := t.checkParams(r); err != nil {
		return err
	}

	token, err := t.tokenManager.QueryByToken(r.Request.Context(), r.Token, r.TokenTypeHint.String())
	if err != nil {
		return err
	}

	if fn := t.clientManager.CheckPermission; fn != nil {
		if allowed := fn(r.Client, token, r.Request); !allowed {
			return autherrors.AccessDeniedError().WithDescription("client does not have permission to inspect token")
		}
	}

	r.Tok = token
	return nil
}

func (t *TokenIntrospection) checkParams(r *IntrospectionRequest) error {
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

func (t *TokenIntrospection) introspectionPayload(r *IntrospectionRequest) map[string]interface{} {
	payload := map[string]interface{}{
		"active": false,
	}
	if r.Tok == nil {
		return payload
	}

	if r.Tok.GetIssuedAt().Add(r.Tok.GetAccessTokenExpiresIn()).Before(time.Now()) {
		return payload
	}

	if fn := t.tokenManager.Inspect; fn != nil {
		payload = fn(r.Client, r.Tok)
	}

	payload["active"] = true
	return payload
}
