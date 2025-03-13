package rfc6749

const (
	ResponseTypeCode           = "code"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeROPC              = "password"
	GrantTypeRefreshToken      = "refresh_token"

	ParamCode         = "code"
	ParamState        = "state"
	ParamTokeType     = "toke_type"
	ParamAccessToken  = "access_token"
	ParamRefreshToken = "refresh_token"
	ParamExpiresIn    = "expires_in"
	ParamScope        = "scope"

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
)
