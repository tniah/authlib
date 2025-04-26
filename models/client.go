package models

import "github.com/tniah/authlib/types"

type Client interface {
	GetClientID() string
	GetClientSecret() string
	GetRedirectURIs() []string
	GetResponseTypes() types.ResponseTypes
	GetGrantTypes() types.GrantTypes
	GetScopes() types.Scopes
	GetAllowedScopes(scopes types.Scopes) types.Scopes
	GetTokenEndpointAuthMethod() types.ClientAuthMethod
	GetDefaultRedirectURI() string
	CheckRedirectURI(redirectURI string) bool
	CheckGrantType(gt types.GrantType) bool
	CheckResponseType(rt types.ResponseType) bool
	CheckTokenEndpointAuthMethod(method types.ClientAuthMethod, endpoint string) bool
	CheckClientSecret(secret string) bool
}
