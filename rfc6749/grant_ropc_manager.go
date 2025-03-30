package rfc6749

import "errors"

var (
	ErrNilClientAuthHandler    = errors.New("\"clientAuthHandler\" cannot be nil")
	ErrNilUserAuthHandler      = errors.New("\"userAuthHandler\" cannot be nil")
	ErrNilAccessTokenGenerator = errors.New("\"accessTokenGenerator\" cannot be nil")
)

type ROPCGrantManager struct {
	grantType            string
	clientAuthHandler    ClientAuthenticationHandler
	userAuthHandler      AuthenticateUser
	accessTokenGenerator AccessTokenGenerator
	clientAuthMethods    map[string]bool
}

func NewROPCGrantManager() *ROPCGrantManager {
	return &ROPCGrantManager{
		grantType:         GrantTypeROPC,
		clientAuthMethods: make(map[string]bool),
	}
}

func (opt *ROPCGrantManager) WithGrantType(gt string) *ROPCGrantManager {
	opt.grantType = gt
	return opt
}

func (opt *ROPCGrantManager) WithClientAuthHandler(h ClientAuthenticationHandler) *ROPCGrantManager {
	opt.clientAuthHandler = h
	return opt
}

func (opt *ROPCGrantManager) WithUserAuthHandler(h AuthenticateUser) *ROPCGrantManager {
	opt.userAuthHandler = h
	return opt
}

func (opt *ROPCGrantManager) WithAccessTokenGenerator(h AccessTokenGenerator) *ROPCGrantManager {
	opt.accessTokenGenerator = h
	return opt
}

func (opt *ROPCGrantManager) WithSupportedClientAuthMethod(method string) *ROPCGrantManager {
	if opt.clientAuthMethods == nil {
		opt.clientAuthMethods = make(map[string]bool)
	}

	opt.clientAuthMethods[method] = true
	return opt
}

func (opt *ROPCGrantManager) Validate() error {
	if opt.clientAuthHandler == nil {
		return ErrNilClientAuthHandler
	}

	if opt.userAuthHandler == nil {
		return ErrNilUserAuthHandler
	}

	if opt.accessTokenGenerator == nil {
		return ErrNilAccessTokenGenerator
	}

	return nil
}
