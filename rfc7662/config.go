package rfc7662

import (
	"errors"
	"github.com/tniah/authlib/types"
)

const EndpointNameTokenIntrospection = "introspection"

var (
	ErrEmptyEndpointName = errors.New("endpoint name is empty")
	ErrNilClientManager  = errors.New("client manager is nil")
	ErrNilTokenManager   = errors.New("token manager is nil")
)

type IntrospectionConfig struct {
	endpointName      string
	clientManager     ClientManager
	tokenManager      TokenManager
	clientAuthMethods map[string]bool
}

func NewIntrospectionConfig() *IntrospectionConfig {
	return &IntrospectionConfig{
		clientAuthMethods: map[string]bool{
			types.ClientBasicAuthentication.String(): true,
		},
		endpointName: EndpointNameTokenIntrospection,
	}
}

func (cfg *IntrospectionConfig) SetEndpointName(name string) *IntrospectionConfig {
	cfg.endpointName = name
	return cfg
}

func (cfg *IntrospectionConfig) SetClientManager(mgr ClientManager) *IntrospectionConfig {
	cfg.clientManager = mgr
	return cfg
}

func (cfg *IntrospectionConfig) SetTokenManager(mgr TokenManager) *IntrospectionConfig {
	cfg.tokenManager = mgr
	return cfg
}

func (cfg *IntrospectionConfig) SetClientAuthMethods(methods map[string]bool) *IntrospectionConfig {
	cfg.clientAuthMethods = methods
	return cfg
}

func (cfg *IntrospectionConfig) ValidateConfig() error {
	if cfg.endpointName == "" {
		return ErrEmptyEndpointName
	}

	if cfg.clientManager == nil {
		return ErrNilClientManager
	}

	if cfg.tokenManager == nil {
		return ErrNilTokenManager
	}

	return nil
}
