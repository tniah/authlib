package authorizationcode

import "errors"

var (
	ErrNilClientManager   = errors.New("client manager is nil")
	ErrNilUserManager     = errors.New("user manager is nil")
	ErrNilAuthCodeManager = errors.New("auth code manager is be nil")
	ErrNilTokenManager    = errors.New("token manager is be nil")
	ErrEmptyAuthMethods   = errors.New("auth methods are empty")
	ErrNilAuthCode        = errors.New("auth code is nil")
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	ResponseTypeCode           = "code"
	EndpointToken              = "token"
	ParamResponseType          = "response_type"
	ParamCode                  = "code"
	ParamState                 = "state"
	ParamTokeType              = "token_type"
	ParamAccessToken           = "access_token"
	ParamRefreshToken          = "refresh_token"
	ParamExpiresIn             = "expires_in"
	ParamScope                 = "scope"
	ParamClientID              = "client_id"
	ParamRedirectURI           = "redirect_uri"
	ParamClientSecret          = "client_secret"

	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodNone              = "none"

	ErrMissingClientID                  = "Missing \"client_id\" in request"
	ErrClientNotFound                   = "No client was found that matches \"client_id\" value"
	ErrMissingRedirectURI               = "Missing \"redirect_uri\" in request"
	ErrUnsupportedRedirectURI           = "\"redirect_uri\" is not supported by client"
	ErrMissingResponseType              = "Missing \"response_type\" in request"
	ErrRequestMustBePOST                = "request must be POST"
	ErrNotContentTypeXWWWFormUrlencoded = "content type must be \"application/x-www-form-urlencoded\""
)
