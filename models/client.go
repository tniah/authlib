package models

type Client interface {
	GetClientID() string
	GetClientSecret() string
	GetRedirectURIs() []string
	GetResponseTypes() []string
	GetGrantTypes() []string
	GetScopes() []string
	GetTokenEndpointAuthMethod() string
	GetAllowedScopes(scopes []string) []string
	GetDefaultRedirectURI() string
	CheckRedirectURI(redirectURI string) bool
	CheckGrantType(grantType string) bool
	CheckResponseType(responseType string) bool
	CheckTokenEndpointAuthMethod(authMethod, endpoint string) bool
	CheckClientSecret(secret string) bool
}
