package authorizationcode

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
	return nil
}
