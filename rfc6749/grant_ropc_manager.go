package rfc6749

import "errors"

var (
	ErrNilClientAuthHandler    = errors.New("\"clientAuthHandler\" cannot be nil")
	ErrNilUserAuthHandler      = errors.New("\"userAuthHandler\" cannot be nil")
	ErrNilAccessTokenGenerator = errors.New("\"accessTokenGenerator\" cannot be nil")
)

type ROPCGrantManager struct {
	clientAuthHandler         ClientAuthenticationHandler
	userAuthHandler           AuthenticateUser
	accessTokenGenerator      AccessTokenGenerator
	supportedTokenAuthMethods map[string]bool
}

func NewROPCGrantManager() *ROPCGrantManager {
	return &ROPCGrantManager{
		supportedTokenAuthMethods: map[string]bool{
			AuthMethodClientSecretBasic: true,
		},
	}
}

func (m *ROPCGrantManager) WithClientAuthHandler(h ClientAuthenticationHandler) *ROPCGrantManager {
	m.clientAuthHandler = h
	return m
}

func (m *ROPCGrantManager) WithUserAuthHandler(h AuthenticateUser) *ROPCGrantManager {
	m.userAuthHandler = h
	return m
}

func (m *ROPCGrantManager) WithAccessTokenGenerator(h AccessTokenGenerator) *ROPCGrantManager {
	m.accessTokenGenerator = h
	return m
}

func (m *ROPCGrantManager) WithSupportedTokenAuthMethod(method string) *ROPCGrantManager {
	if m.supportedTokenAuthMethods == nil {
		m.supportedTokenAuthMethods = make(map[string]bool)
	}

	m.supportedTokenAuthMethods[method] = true
	return m
}

func (m *ROPCGrantManager) Validate() error {
	if m.clientAuthHandler == nil {
		return ErrNilClientAuthHandler
	}

	if m.userAuthHandler == nil {
		return ErrNilUserAuthHandler
	}

	if m.accessTokenGenerator == nil {
		return ErrNilAccessTokenGenerator
	}

	return nil
}
