package rfc7662

import "errors"

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
			AuthMethodClientSecretBasic: true,
		},
		endpointName: EndpointNameTokenIntrospection,
	}
}

func (opts *IntrospectionConfig) SetEndpointName(name string) *IntrospectionConfig {
	opts.endpointName = name
	return opts
}

func (opts *IntrospectionConfig) SetClientManager(mgr ClientManager) *IntrospectionConfig {
	opts.clientManager = mgr
	return opts
}

func (opts *IntrospectionConfig) SetTokenManager(mgr TokenManager) *IntrospectionConfig {
	opts.tokenManager = mgr
	return opts
}

func (opts *IntrospectionConfig) SetClientAuthMethods(methods map[string]bool) *IntrospectionConfig {
	opts.clientAuthMethods = methods
	return opts
}

func (opts *IntrospectionConfig) Validate() error {
	if opts.endpointName == "" {
		return ErrEmptyEndpointName
	}

	if opts.clientManager == nil {
		return ErrNilClientManager
	}

	if opts.tokenManager == nil {
		return ErrNilTokenManager
	}

	return nil
}
