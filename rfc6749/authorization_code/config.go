package authorizationcode

import "errors"

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
	supportedClientAuthMethods map[string]bool
}

func NewConfig() *Config {
	return &Config{
		supportedClientAuthMethods: map[string]bool{
			AuthMethodClientSecretBasic: true,
			AuthMethodNone:              true,
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

func (cfg *Config) SetAuthCodeManager(mgr AuthCodeManager) *Config {
	cfg.authCodeMgr = mgr
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

	if cfg.supportedClientAuthMethods == nil || len(cfg.supportedClientAuthMethods) == 0 {
		return ErrEmptyClientAuthMethods
	}

	return nil
}
