package rfc7662

import (
	"errors"
	"github.com/tniah/authlib/types"
)

const EndpointNameTokenIntrospection = "introspection"

var (
	ErrEmptyEndpointName      = errors.New("endpoint name is empty")
	ErrNilClientManager       = errors.New("client manager is nil")
	ErrNilTokenManager        = errors.New("token manager is nil")
	ErrEmptyClientAuthMethods = errors.New("supported client auth methods are empty")
)

type Config struct {
	endpointName               string
	clientManager              ClientManager
	tokenManager               TokenManager
	supportedClientAuthMethods map[types.ClientAuthMethod]bool
}

func NewConfig() *Config {
	return &Config{
		supportedClientAuthMethods: map[types.ClientAuthMethod]bool{
			types.ClientBasicAuthentication: true,
		},
		endpointName: EndpointNameTokenIntrospection,
	}
}

func (cfg *Config) SetEndpointName(name string) *Config {
	cfg.endpointName = name
	return cfg
}

func (cfg *Config) SetClientManager(mgr ClientManager) *Config {
	cfg.clientManager = mgr
	return cfg
}

func (cfg *Config) SetTokenManager(mgr TokenManager) *Config {
	cfg.tokenManager = mgr
	return cfg
}

func (cfg *Config) SetSupportedClientAuthMethods(methods map[types.ClientAuthMethod]bool) *Config {
	cfg.supportedClientAuthMethods = methods
	return cfg
}

func (cfg *Config) ValidateConfig() error {
	if cfg.endpointName == "" {
		return ErrEmptyEndpointName
	}

	if cfg.clientManager == nil {
		return ErrNilClientManager
	}

	if cfg.tokenManager == nil {
		return ErrNilTokenManager
	}

	if cfg.supportedClientAuthMethods == nil {
		return ErrEmptyClientAuthMethods
	}

	return nil
}
