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
	clientAuthHandler         ClientAuthHandler
	clientPermissionHandler   ClientPermissionHandler
	tokenQueryHandler         TokenQueryHandler
	tokenIntrospectionHandler TokenIntrospectionHandler
	clientAuthMethods         map[string]bool
	endpointName              string
}

func NewTokenIntrospection() *TokenIntrospection {
	return &TokenIntrospection{
		clientAuthMethods: map[string]bool{
			AuthMethodClientSecretBasic: true,
		},
		endpointName: EndpointNameTokenIntrospection,
	}
}

func (t *TokenIntrospection) WithClientAuthHandler(h ClientAuthHandler) *TokenIntrospection {
	t.clientAuthHandler = h
	return t
}

func (t *TokenIntrospection) MustClientAuthHandler(h ClientAuthHandler) *TokenIntrospection {
	if h == nil {
		panic(ErrNilClientAuthHandler)
	}

	return t.WithClientAuthHandler(h)
}

func (t *TokenIntrospection) WithClientPermissionHandler(h ClientPermissionHandler) *TokenIntrospection {
	t.clientPermissionHandler = h
	return t
}

func (t *TokenIntrospection) MustClientPermissionHandler(h ClientPermissionHandler) *TokenIntrospection {
	if h == nil {
		panic(ErrNilClientPermissionHandler)
	}

	return t.WithClientPermissionHandler(h)
}

func (t *TokenIntrospection) WithTokenQueryHandler(h TokenQueryHandler) *TokenIntrospection {
	t.tokenQueryHandler = h
	return t
}

func (t *TokenIntrospection) MustTokenQueryHandler(h TokenQueryHandler) *TokenIntrospection {
	if h == nil {
		panic(ErrNilTokenQueryHandler)
	}

	return t.WithTokenQueryHandler(h)
}

func (t *TokenIntrospection) WithTokenIntrospectionHandler(h TokenIntrospectionHandler) *TokenIntrospection {
	t.tokenIntrospectionHandler = h
	return t
}

func (t *TokenIntrospection) MustTokenIntrospectionHandler(h TokenIntrospectionHandler) *TokenIntrospection {
	if h == nil {
		panic(ErrNilTokenIntrospectionHandler)
	}

	return t.WithTokenIntrospectionHandler(h)
}

func (t *TokenIntrospection) RegisterClientAuthMethod(method string) {
	if t.clientAuthMethods == nil {
		t.clientAuthMethods = make(map[string]bool)
	}

	t.clientAuthMethods[method] = true
}

func (t *TokenIntrospection) EndpointName() string {
	if t.endpointName == "" {
		return EndpointNameTokenIntrospection
	}

	return t.endpointName
}

func (t *TokenIntrospection) EndpointResponse(r *http.Request, rw http.ResponseWriter) error {
	client, err := t.clientAuthHandler(r, t.clientAuthMethods, t.EndpointName())
	if err != nil {
		return err
	}

	token, err := t.authenticateToken(r, client)
	if err != nil {
		return err
	}

	payload := t.introspectionPayload(token)
	return t.jsonResponse(rw, payload)
}

func (t *TokenIntrospection) authenticateToken(r *http.Request, client models.Client) (models.Token, error) {
	if err := t.checkParams(r); err != nil {
		return nil, err
	}

	token, err := t.tokenQueryHandler(r.Context(), r.FormValue(ParamToken), r.PostFormValue(ParamTokenTypeHint))
	if err != nil {
		return nil, err
	}

	if fn := t.clientPermissionHandler; fn != nil {
		if allowed := fn(r, client, token); !allowed {
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
	if ct != ContentTypeXWWWFormUrlEncoded {
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

func (t *TokenIntrospection) introspectionPayload(token models.Token) map[string]interface{} {
	payload := map[string]interface{}{
		"active": false,
	}
	if token == nil {
		return payload
	}

	if token.GetIssuedAt().Add(token.GetAccessTokenExpiresIn()).Before(time.Now()) {
		return payload
	}

	if fn := t.tokenIntrospectionHandler; fn != nil {
		payload = fn(token)
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
