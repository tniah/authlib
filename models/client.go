package models

type Client interface {
	GetClientID() string
	GetClientSecret() string
	GetRedirectURIs() []string
	GetResponseTypes() []string
	GetGrantTypes() []string
	GetScopes() []string
	GetTokenEndpointAuthMethod() string
	GetDefaultRedirectURI() string
	GetAllowedScopes(scopes []string) []string
	CheckRedirectURI(redirectURI string) bool
	CheckResponseType(responseType string) bool
	CheckTokenEndpointAuthMethod(authMethod string) bool
	CheckClientSecret(secret string) bool
	CheckGrantType(grantType string) bool
}
