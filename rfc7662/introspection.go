package rfc7662

import (
	"encoding/json"
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"mime"
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
	if err := cfg.Validate(); err != nil {
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

	token, err := t.authenticateToken(r, client)
	if err != nil {
		return err
	}

	payload := t.introspectionPayload(token, client)
	return t.jsonResponse(rw, payload)
}

func (t *TokenIntrospection) authenticateToken(r *http.Request, client models.Client) (models.Token, error) {
	if err := t.checkParams(r); err != nil {
		return nil, err
	}

	token, err := t.tokenManager.QueryByToken(r.Context(), r.FormValue(ParamToken), r.PostFormValue(ParamTokenTypeHint))
	if err != nil {
		return nil, err
	}

	if fn := t.clientManager.CheckPermission; fn != nil {
		if allowed := fn(client, token, r); !allowed {
			return nil, autherrors.AccessDeniedError().WithDescription(ErrClientDoesNotHavePermission)
		}
	}

	return token, nil
}

func (t *TokenIntrospection) checkParams(r *http.Request) error {
	if r.Method != http.MethodPost {
		return autherrors.InvalidRequestError().WithDescription(ErrRequestMustBePost)
	}

	ct, _, err := mime.ParseMediaType(r.Header.Get(HeaderContentType))
	if err != nil {
		return autherrors.InvalidRequestError()
	}
	if ct != ContentTypeXWwwFormUrlEncoded {
		return autherrors.InvalidRequestError().WithDescription(ErrInvalidContentType)
	}

	token := r.PostFormValue(ParamToken)
	if token == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrTokenParamMissing)
	}

	hint := r.PostFormValue(ParamTokenTypeHint)
	if hint != "" && hint != TokenTypeHintAccessToken && hint != TokenTypeHintRefreshToken {
		return autherrors.UnsupportedTokenType().WithDescription(ErrInvalidTokenTypeHint)
	}

	return nil
}

func (t *TokenIntrospection) introspectionPayload(token models.Token, client models.Client) map[string]interface{} {
	payload := map[string]interface{}{
		"active": false,
	}
	if token == nil {
		return payload
	}

	if token.GetIssuedAt().Add(token.GetAccessTokenExpiresIn()).Before(time.Now()) {
		return payload
	}

	if fn := t.tokenManager.Inspect; fn != nil {
		payload = fn(client, token)
	}

	payload["active"] = true
	return payload
}

func (t *TokenIntrospection) jsonResponse(rw http.ResponseWriter, payload map[string]interface{}) error {
	for k, v := range common.DefaultJSONHeader() {
		rw.Header().Set(k, v)
	}

	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(payload)
}
