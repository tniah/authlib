package models

import "github.com/tniah/authlib/constants"

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
	CheckResponseType(responseType constants.ResponseType) bool
	CheckTokenEndpointAuthMethod(authMethod constants.TokenEndpointAuthMethodType) bool
	CheckClientSecret(secret string) bool
	CheckGrantType(grantType constants.GrantType) bool
}
