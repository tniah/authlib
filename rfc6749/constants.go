package rfc6749

import "errors"

const (
	HeaderContentType             = "Content-Type"
	ContentTypeXWwwFormUrlEncoded = "application/x-www-form-urlencoded"

	ResponseTypeCode           = "code"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeROPC              = "password"
	GrantTypeRefreshToken      = "refresh_token"

	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodNone              = "none"

	EndpointNameToken = "token"

	ParamResponseType = "response_type"
	ParamCode         = "code"
	ParamState        = "state"
	ParamTokeType     = "token_type"
	ParamAccessToken  = "access_token"
	ParamRefreshToken = "refresh_token"
	ParamExpiresIn    = "expires_in"
	ParamScope        = "scope"
	ParamClientID     = "client_id"
	ParamRedirectURI  = "redirect_uri"
	ParamClientSecret = "client_secret"
	ParamUsername     = "username"
	ParamPassword     = "password"

	ErrRequestMustBePost           = "request must be POST"
	ErrRequestMustBeGetOrPost      = "request must be GET or POST"
	ErrNotXWwwFormUrlencoded       = "content type must be \"application/x-www-form-urlencoded\""
	ErrMissingClientID             = "Missing \"client_id\" in request"
	ErrClientIDNotFound            = "No client was found that matches \"client_id\" value"
	ErrMissingRedirectURI          = "Missing \"redirect_uri\" in request"
	ErrUnsupportedRedirectURI      = "Redirect URI is not supported by client"
	ErrInvalidRedirectURI          = "Invalid \"redirect_uri\" in request"
	ErrUnsupportedGrantType        = "The client is not authorized to use grant type \"authorization_code\""
	ErrUnsupportedROPCGrant        = "The client is not authorized to use grant type \"password\""
	ErrMissingCode                 = "Missing \"code\" in request"
	ErrInvalidCode                 = "Invalid \"code\" in request"
	ErrUserNotFound                = "No user could be found associated with this authorization code"
	ErrMissingUsername             = "Missing \"username\" in request"
	ErrMissingPassword             = "Missing \"password\" in request"
	ErrUsernameOrPasswordIncorrect = "Username or password is incorrect"

	ErrMissingResponseType = "Missing \"response_type\" in request"
)

var (
	ErrClientQueryHandlerIsNil   = errors.New("\"clientQueryHandler\" cannot be nil")
	ErrClientAuthHandlerIsNil    = errors.New("\"clientAuthHandler\" cannot be nil")
	ErrUserQueryHandlerIsNil     = errors.New("\"userQueryHandler\" cannot be nil")
	ErrUserAuthHandlerIsNil      = errors.New("\"userAuthHandler\" cannot be nil")
	ErrAccessTokenGeneratorIsNil = errors.New("\"accessTokenGenerator\" cannot be nil")
)
