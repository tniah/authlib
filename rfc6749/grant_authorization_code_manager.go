package rfc6749

type AuthCodeGrantManager struct {
	clientQueryHandler        ClientQueryHandler
	clientAuthHandler         ClientAuthenticationHandler
	userQueryHandler          UserQueryHandler
	accessTokenGenerator      AccessTokenGenerator
	supportedTokenAuthMethods map[string]bool
}

func NewAuthCodeGrantManager() *AuthCodeGrantManager {
	return &AuthCodeGrantManager{
		supportedTokenAuthMethods: map[string]bool{
			AuthMethodClientSecretBasic: true,
			AuthMethodNone:              true,
		},
	}
}

func (m *AuthCodeGrantManager) WithClientQueryHandler(h ClientQueryHandler) *AuthCodeGrantManager {
	m.clientQueryHandler = h
	return m
}

func (m *AuthCodeGrantManager) WithClientAuthHandler(h ClientAuthenticationHandler) *AuthCodeGrantManager {
	m.clientAuthHandler = h
	return m
}

func (m *AuthCodeGrantManager) WithAccessTokenGenerator(h AccessTokenGenerator) *AuthCodeGrantManager {
	m.accessTokenGenerator = h
	return m
}

func (m *AuthCodeGrantManager) Validate() error {
	if m.clientQueryHandler == nil {
		return ErrClientQueryHandlerIsNil
	}

	if m.clientAuthHandler == nil {
		return ErrClientAuthHandlerIsNil
	}

	if m.userQueryHandler == nil {
		return ErrUserQueryHandlerIsNil
	}

	return nil
}
