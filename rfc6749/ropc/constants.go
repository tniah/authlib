package ropc

const (
	GrantTypeROPC               = "password"
	GrantTypeRefreshToken       = "refresh_token"
	EndpointToken               = "token"
	AuthMethodClientSecretBasic = "client_secret_basic"
	ParamGrantType              = "grant_type"
	ParamScope                  = "scope"
	ParamUsername               = "username"
	ParamPassword               = "password"

	ErrMissingGrantType            = "Missing \"grant_type\" in request"
	ErrMissingUsername             = "Missing \"username\" in request"
	ErrMissingPassword             = "Missing \"password\" in request"
	ErrIncorrectUsernameOrPassword = "Username or password is incorrect"
	ErrClientUnsupportedROPC       = "The client is not authorized to use grant type \"password\""
)
