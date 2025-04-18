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
	GetAllowedScopes(scopes []string) []string
	GetDefaultRedirectURI() string
	CheckRedirectURI(redirectURI string) bool
	CheckGrantType(gt types.GrantType) bool
	CheckResponseType(rt types.ResponseType) bool
	CheckTokenEndpointAuthMethod(authMethod, endpoint string) bool
	CheckClientSecret(secret string) bool
}
