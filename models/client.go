package models

import "github.com/tniah/authlib/types"

type Client interface {
	GetClientID() string
	GetClientSecret() string
	GetRedirectURIs() []string
	GetResponseTypes() []string
	GetGrantTypes() []string
	GetScopes() []string
	GetTokenEndpointAuthMethod() string
	GetAllowedScopes(scopes types.Scopes) types.Scopes
	GetDefaultRedirectURI() string
	CheckRedirectURI(redirectURI string) bool
	CheckGrantType(gt string) bool
	CheckResponseType(rt string) bool
	CheckTokenEndpointAuthMethod(authMethod, endpoint string) bool
	CheckClientSecret(secret string) bool
}
