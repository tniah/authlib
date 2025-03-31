package ropc

const (
	GrantTypeROPC               = "password"
	GrantTypeRefreshToken       = "refresh_token"
	EndpointToken               = "token"
	AuthMethodClientSecretBasic = "client_secret_basic"

	ErrRequestMustBePOST                = "request must be POST"
	ErrNotContentTypeXWWWFormUrlencoded = "content type must be \"application/x-www-form-urlencoded\""
	ErrMissingUsername                  = "Missing \"username\" in request"
	ErrMissingPassword                  = "Missing \"password\" in request"
	ErrIncorrectUsernameOrPassword      = "Username or password is incorrect"
	ErrClientUnsupportedROPC            = "The client is not authorized to use grant type \"password\""
)
