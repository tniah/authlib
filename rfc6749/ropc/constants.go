package ropc

import "errors"

var (
	ErrNilClientManager = errors.New("client manager is nil")
	ErrNilUserManager   = errors.New("user manager is nil")
	ErrNilTokenManager  = errors.New("token manager is nil")
)

const (
	GrantTypeROPC               = "password"
	GrantTypeRefreshToken       = "refresh_token"
	EndpointToken               = "token"
	AuthMethodClientSecretBasic = "client_secret_basic"
	ParamScope                  = "scope"
	ParamUsername               = "username"
	ParamPassword               = "password"

	ErrMissingUsername             = "Missing \"username\" in request"
	ErrMissingPassword             = "Missing \"password\" in request"
	ErrIncorrectUsernameOrPassword = "Username or password is incorrect"
	ErrClientUnsupportedROPC       = "The client is not authorized to use grant type \"password\""
)
