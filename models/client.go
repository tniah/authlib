package models

import "github.com/tniah/authlib/types"

type Client interface {
	GetClientID() string
	GetAllowedScopes(scopes types.Scopes) types.Scopes
	GetDefaultRedirectURI() string
	CheckRedirectURI(redirectURI string) bool
	CheckGrantType(gt types.GrantType) bool
	CheckResponseType(rt types.ResponseType) bool
	CheckTokenEndpointAuthMethod(method types.ClientAuthMethod, endpoint string) bool
	CheckClientSecret(secret string) bool
}
