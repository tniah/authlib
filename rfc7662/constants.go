package rfc7662

import "errors"

const (
	EndpointNameTokenIntrospection = "introspection"
	AuthMethodClientSecretBasic    = "client_secret_basic"

	HeaderContentType             = "Content-Type"
	ContentTypeXWwwFormUrlEncoded = "application/x-www-form-urlencoded"

	ParamToken         = "token"
	ParamTokenTypeHint = "token_type_hint"

	TokenTypeHintAccessToken  = "access_token"
	TokenTypeHintRefreshToken = "refresh_token"

	ErrRequestMustBePost           = "request must be POST"
	ErrInvalidContentType          = "content type must be \"application/x-www-form-urlencoded\""
	ErrTokenParamMissing           = "\"token\" is empty or missing"
	ErrInvalidTokenTypeHint        = "token type hint must be set to \"access_token\" or \"refresh_token\""
	ErrClientDoesNotHavePermission = "client does not have permission to inspect token"
)

var (
	ErrNilClientAuthHandler         = errors.New("\"clientAuthHandler\" is nil")
	ErrNilClientPermissionHandler   = errors.New("\"clientPermissionHandler\" is nil")
	ErrNilTokenQueryHandler         = errors.New("\"tokenQueryHandler\" is nil")
	ErrNilTokenIntrospectionHandler = errors.New("\"tokenIntrospectionHandler\" is nil")
)
