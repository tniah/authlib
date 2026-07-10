package ropc

import (
	"errors"
	"net/http"

	"github.com/tniah/authlib/types"
)

var (
	ErrNilClientManager       = errors.New("client manager is nil")
	ErrNilUserManager         = errors.New("user manager is nil")
	ErrNilTokenManager        = errors.New("token manager is nil")
	ErrEmptyClientAuthMethods = errors.New("client auth methods are empty")
)

// Config holds all dependencies and extension hooks for the ROPC flow.
// Use NewConfig() to get a config with sensible defaults, then chain Set*/RegisterExtension
// calls before passing to Must() or New().
type Config struct {
	clientMgr ClientManager
	userMgr   UserManager
	tokenMgr  TokenManager

	tokenEndpointHttpMethods []string

	// Extension slices are executed in registration order.
	tokenReqValidators []TokenRequestValidator
	tokenProcessors    []TokenProcessor

	// supportedClientAuthMethods controls which client authentication methods
	// are accepted at the token endpoint. ROPC defaults to basic auth only.
	supportedClientAuthMethods map[types.ClientAuthMethod]bool
}

// NewConfig returns a Config with secure defaults:
//   - Accepts POST on /token.
//   - Supports basic client authentication only (client_secret_basic).
func NewConfig() *Config {
	return &Config{
		tokenEndpointHttpMethods: []string{http.MethodPost},
		tokenReqValidators:       []TokenRequestValidator{},
		tokenProcessors:          []TokenProcessor{},
		supportedClientAuthMethods: map[types.ClientAuthMethod]bool{
			types.ClientBasicAuthentication: true,
		},
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

func (cfg *Config) SetSupportedClientAuthMethods(methods map[types.ClientAuthMethod]bool) *Config {
	cfg.supportedClientAuthMethods = methods
	return cfg
}

func (cfg *Config) SetTokenEndpointHttpMethods(methods []string) *Config {
	cfg.tokenEndpointHttpMethods = methods
	return cfg
}

// RegisterExtension adds ext to every extension slice whose interface it satisfies.
// A single object may implement both TokenRequestValidator and TokenProcessor.
func (cfg *Config) RegisterExtension(ext interface{}) *Config {
	if h, ok := ext.(TokenRequestValidator); ok {
		cfg.tokenReqValidators = append(cfg.tokenReqValidators, h)
	}

	if h, ok := ext.(TokenProcessor); ok {
		cfg.tokenProcessors = append(cfg.tokenProcessors, h)
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

	if len(cfg.supportedClientAuthMethods) == 0 {
		return ErrEmptyClientAuthMethods
	}

	return nil
}
