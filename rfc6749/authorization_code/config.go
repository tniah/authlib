package authorizationcode

import (
	"errors"
	"net/http"

	"github.com/tniah/authlib/types"
)

var (
	ErrNilClientManager       = errors.New("client manager is nil")
	ErrNilUserManager         = errors.New("user manager is nil")
	ErrNilAuthCodeManager     = errors.New("auth code manager is nil")
	ErrNilTokenManager        = errors.New("token manager is nil")
	ErrEmptyClientAuthMethods = errors.New("client auth methods are empty")
)

// Config holds all dependencies and extension hooks for the Authorization Code flow.
// Use NewConfig() to get a config with sensible defaults, then chain Set*/RegisterExtension
// calls before passing to Must() or New().
type Config struct {
	clientMgr   ClientManager
	userMgr     UserManager
	authCodeMgr AuthCodeManager
	tokenMgr    TokenManager

	authEndpointHttpMethods  []string
	tokenEndpointHttpMethods []string

	// Extension slices are executed in registration order. A single object may
	// implement multiple extension interfaces and will be appended to each
	// applicable slice (e.g. PKCE registers as both AuthCodeProcessor and
	// TokenRequestValidator).
	authReqValidators    []AuthorizationRequestValidator
	consentReqValidators []ConsentRequestValidator
	authCodeProcessors   []AuthCodeProcessor
	tokenReqValidators   []TokenRequestValidator
	tokenProcessors      []TokenProcessor

	// supportedClientAuthMethods controls which authentication methods are
	// accepted at the token endpoint (basic, post, none).
	supportedClientAuthMethods map[types.ClientAuthMethod]bool
}

// NewConfig returns a Config with secure defaults:
//   - Accepts GET on /authorize, POST on /token.
//   - Supports basic and none client authentication methods.
func NewConfig() *Config {
	return &Config{
		supportedClientAuthMethods: map[types.ClientAuthMethod]bool{
			types.ClientBasicAuthentication: true,
			types.ClientNoneAuthentication:  true,
		},
		authEndpointHttpMethods:  []string{http.MethodGet},
		tokenEndpointHttpMethods: []string{http.MethodPost},
		authReqValidators:        []AuthorizationRequestValidator{},
		consentReqValidators:     []ConsentRequestValidator{},
		authCodeProcessors:       []AuthCodeProcessor{},
		tokenReqValidators:       []TokenRequestValidator{},
		tokenProcessors:          []TokenProcessor{},
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

// RegisterExtension adds ext to every extension slice whose interface it satisfies.
// Call this once per extension object; it will automatically register for all
// applicable hooks (e.g. a PKCE object implements both AuthCodeProcessor and
// TokenRequestValidator, so it is added to both slices in one call).
func (cfg *Config) RegisterExtension(ext interface{}) *Config {
	if h, ok := ext.(AuthorizationRequestValidator); ok {
		cfg.authReqValidators = append(cfg.authReqValidators, h)
	}

	if h, ok := ext.(ConsentRequestValidator); ok {
		cfg.consentReqValidators = append(cfg.consentReqValidators, h)
	}

	if h, ok := ext.(AuthCodeProcessor); ok {
		cfg.authCodeProcessors = append(cfg.authCodeProcessors, h)
	}

	if h, ok := ext.(TokenRequestValidator); ok {
		cfg.tokenReqValidators = append(cfg.tokenReqValidators, h)
	}

	if h, ok := ext.(TokenProcessor); ok {
		cfg.tokenProcessors = append(cfg.tokenProcessors, h)
	}

	return cfg
}

func (cfg *Config) SetSupportedClientAuthMethods(methods map[types.ClientAuthMethod]bool) *Config {
	cfg.supportedClientAuthMethods = methods
	return cfg
}

func (cfg *Config) ValidateConfig() error {
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
