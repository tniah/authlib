package authorizationcode

const (
	AuthCodeLength             = 48
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	ResponseTypeCode           = "code"
	EndpointToken              = "token"
	ParamResponseType          = "response_type"
	ParamCode                  = "code"
	ParamState                 = "state"
	ParamScope                 = "scope"
	ParamClientID              = "client_id"
	ParamRedirectURI           = "redirect_uri"
	ParamGrantType             = "grant_type"

	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodNone              = "none"

	ErrMissingClientID        = "Missing \"client_id\" in request"
	ErrClientNotFound         = "No client was found that matches \"client_id\" value"
	ErrMissingRedirectURI     = "Missing \"redirect_uri\" in request"
	ErrUnsupportedRedirectURI = "\"redirect_uri\" is not supported by client"
	ErrMissingResponseType    = "Missing \"response_type\" in request"
	ErrMissingGrantType       = "Missing \"grant_type\" in request"
	ErrMissingAuthCode        = "Missing \"code\" in request"
	ErrInvalidAuthCode        = "Invalid \"code\" in request"
	ErrUserNotFound           = "No user could be found associated with this authorization code"
	ErrInvalidRedirectURI     = "Invalid \"redirect_uri\" in request"
)
