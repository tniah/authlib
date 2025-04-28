package authorizationcode

import (
	"errors"
	"github.com/tniah/authlib/types"
	"net/http"
)

var (
	ErrNilClientManager       = errors.New("client manager is nil")
	ErrNilUserManager         = errors.New("user manager is nil")
	ErrNilAuthCodeManager     = errors.New("auth code manager is nil")
	ErrNilTokenManager        = errors.New("token manager is nil")
	ErrEmptyClientAuthMethods = errors.New("client auth methods are empty")
)

type Config struct {
	clientMgr                  ClientManager
	userMgr                    UserManager
	authCodeMgr                AuthCodeManager
	tokenMgr                   TokenManager
	authEndpointHttpMethods    []string
	tokenEndpointHttpMethods   []string
	authReqValidators          map[AuthorizationRequestValidator]bool
	consentReqValidators       map[ConsentRequestValidator]bool
	authCodeProcessors         map[AuthCodeProcessor]bool
	tokenReqValidators         map[TokenRequestValidator]bool
	tokenProcessors            map[TokenProcessor]bool
	supportedClientAuthMethods map[types.ClientAuthMethod]bool
}

func NewConfig() *Config {
	return &Config{
		supportedClientAuthMethods: map[types.ClientAuthMethod]bool{
			types.ClientBasicAuthentication: true,
			types.ClientNoneAuthentication:  true,
		},
		authEndpointHttpMethods:  []string{http.MethodGet},
		tokenEndpointHttpMethods: []string{http.MethodPost},
		authReqValidators:        map[AuthorizationRequestValidator]bool{},
		consentReqValidators:     map[ConsentRequestValidator]bool{},
		authCodeProcessors:       map[AuthCodeProcessor]bool{},
		tokenReqValidators:       map[TokenRequestValidator]bool{},
		tokenProcessors:          map[TokenProcessor]bool{},
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

func (cfg *Config) SetAuthCodeManager(mgr AuthCodeManager) *Config {
	cfg.authCodeMgr = mgr
	return cfg
}

func (cfg *Config) SetTokenManager(mgr TokenManager) *Config {
	cfg.tokenMgr = mgr
	return cfg
}

func (cfg *Config) SetAuthEndpointHttpMethods(methods []string) *Config {
	cfg.authEndpointHttpMethods = methods
	return cfg
}

func (cfg *Config) SetTokenEndpointHttpMethods(methods []string) *Config {
	cfg.tokenEndpointHttpMethods = methods
	return cfg
}

func (cfg *Config) RegisterExtension(ext interface{}) *Config {
	if h, ok := ext.(AuthorizationRequestValidator); ok {
		if cfg.authReqValidators == nil {
			cfg.authReqValidators = map[AuthorizationRequestValidator]bool{}
		}

		cfg.authReqValidators[h] = true
	}

	if h, ok := ext.(ConsentRequestValidator); ok {
		if cfg.consentReqValidators == nil {
			cfg.consentReqValidators = map[ConsentRequestValidator]bool{}
		}

		cfg.consentReqValidators[h] = true
	}

	if h, ok := ext.(AuthCodeProcessor); ok {
		if cfg.authCodeProcessors == nil {
			cfg.authCodeProcessors = map[AuthCodeProcessor]bool{}
		}

		cfg.authCodeProcessors[h] = true
	}

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

func (cfg *Config) SetSupportedClientAuthMethods(methods map[types.ClientAuthMethod]bool) *Config {
	cfg.supportedClientAuthMethods = methods
	return cfg
}

func (cfg *Config) Validate() error {
	if cfg.clientMgr == nil {
		return ErrNilClientManager
	}

	if cfg.userMgr == nil {
		return ErrNilUserManager
	}

	if cfg.authCodeMgr == nil {
		return ErrNilAuthCodeManager
	}

	if cfg.tokenMgr == nil {
		return ErrNilTokenManager
	}

	if len(cfg.supportedClientAuthMethods) == 0 {
		return ErrEmptyClientAuthMethods
	}

	return nil
}
