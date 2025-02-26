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
	CheckRedirectURI(redirectURI string) bool
	CheckResponseType(responseType string) bool
	CheckTokenEndpointAuthMethod(authMethod string) bool
}
