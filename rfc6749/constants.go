package rfc6749

const (
	ErrMissingClientID        = "Missing \"client_id\" parameter in request"
	ErrClientIDNotFound       = "No client was found that matches \"client_id\" value"
	ErrMissingRedirectURI     = "Missing \"redirect_uri\" parameter in request"
	ErrUnsupportedRedirectURI = "Redirect URI is not supported by client"
	ErrInvalidRedirectURI     = "Invalid \"redirect_uri\" in request"
	ErrUnsupportedGrantType   = "The client is not authorized to use grant type \"authorization_code\""
	ErrMissingCode            = "Missing \"code\" parameter in request"
	ErrInvalidCode            = "Invalid \"code\" in request"
	ErrUserNotFound           = "No user could be found associated with this authorization code"
	ParamAccessToken          = "access_token"
	ParamRefreshToken         = "refresh_token"
	ParamTokenType            = "token_type"
	ParamExpiresIn            = "expires_in"
	ParamScope                = "scope"
)
