package ropc

import (
	"errors"
	"net/http"
)

var (
	ErrNilClientManager       = errors.New("client manager is nil")
	ErrNilUserManager         = errors.New("user manager is nil")
	ErrNilTokenManager        = errors.New("token manager is nil")
	ErrEmptyClientAuthMethods = errors.New("client auth methods are empty")
)

type Config struct {
	clientMgr                  ClientManager
	userMgr                    UserManager
	tokenMgr                   TokenManager
	tokenEndpointHttpMethods   []string
	tokenReqValidators         map[TokenRequestValidator]bool
	tokenProcessors            map[TokenProcessor]bool
	supportedClientAuthMethods map[string]bool
}

func NewConfig() *Config {
	return &Config{
		tokenEndpointHttpMethods: []string{http.MethodPost},
		supportedClientAuthMethods: map[string]bool{
			"client_secret_basic": true,
		},
		tokenReqValidators: map[TokenRequestValidator]bool{},
		tokenProcessors:    map[TokenProcessor]bool{},
	}
}

func (cfg *Config) SetClientManager(mgr ClientManager) *Config {
	cfg.clientMgr = mgr
	return cfg
}

func (cfg *Config) SetUserManager(mgr UserManager) *Config {
	cfg.userMgr = mgr
	return cfg
}

func (cfg *Config) SetTokenManager(mgr TokenManager) *Config {
	cfg.tokenMgr = mgr
	return cfg
}

func (cfg *Config) SetSupportedClientAuthMethods(methods map[string]bool) *Config {
	cfg.supportedClientAuthMethods = methods
	return cfg
}

func (cfg *Config) SetTokenEndpointHttpMethods(methods []string) *Config {
	cfg.tokenEndpointHttpMethods = methods
	return cfg
}

func (cfg *Config) RegisterExtension(ext interface{}) *Config {
	if h, ok := ext.(TokenRequestValidator); ok {
		if cfg.tokenReqValidators == nil {
			cfg.tokenReqValidators = map[TokenRequestValidator]bool{}
		}

		cfg.tokenReqValidators[h] = true
	}

	if h, ok := ext.(TokenProcessor); ok {
		if cfg.tokenProcessors == nil {
			cfg.tokenProcessors = map[TokenProcessor]bool{}
		}

		cfg.tokenProcessors[h] = true
	}

	return cfg
}

func (cfg *Config) ValidateConfig() error {
	if cfg.clientMgr == nil {
		return ErrNilClientManager
	}

	if cfg.userMgr == nil {
		return ErrNilUserManager
	}

	if cfg.tokenMgr == nil {
		return ErrNilTokenManager
	}

	if cfg.supportedClientAuthMethods == nil || len(cfg.supportedClientAuthMethods) == 0 {
		return ErrEmptyClientAuthMethods
	}

	return nil
}
