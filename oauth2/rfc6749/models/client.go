package models

import (
	"github.com/tniah/authlib/oauth2/rfc6749"
	"github.com/tniah/authlib/oauth2/rfc6749/grants"
)

type OAuthClient interface {
	GetClientID() string
	GetClientSecret() string
	IsPublic() bool
	GetDefaultRedirectURI() string
	GetAllowedScopes(scopes []string) []string
	CheckRedirectURI(redirectURI string) bool
	CheckClientSecret(secret string) bool
	CheckTokenEndpointAuthMethod(method string) bool
	CheckResponseType(responseType grants.ResponseType) bool
	CheckGrantType(grantType string) bool
}

type OAuth2ClientMixin struct {
	ClientID                string
	ClientSecret            string
	ClientName              string
	RedirectURIs            []string
	GrantTypes              []string
	Scopes                  []string
	ClientURI               string
	LogoURI                 string
	Contacts                []string
	TokenEndpointAuthMethod string
	TosURI                  string
	PolicyURI               string
	JwksURI                 string
	SoftwareID              string
	SoftwareVersion         string
}

func (c *OAuth2ClientMixin) GetClientID() string {
	return c.ClientID
}

func (c *OAuth2ClientMixin) GetClientSecret() string {
	return c.ClientSecret
}

func (c *OAuth2ClientMixin) IsPublic() bool {
	return rfc6749.TokenEndpointAuthMethodType(c.TokenEndpointAuthMethod) == rfc6749.AuthMethodNone
}

func (c *OAuth2ClientMixin) GetDefaultRedirectURI() string {
	if len(c.RedirectURIs) == 0 {
		return ""
	}

	return c.RedirectURIs[0]
}

func (c *OAuth2ClientMixin) GetAllowedScopes(scopes []string) []string {
	m := make(map[string]bool, len(c.Scopes))
	for _, allowed := range c.Scopes {
		m[allowed] = true
	}

	ret := make([]string, 0)
	for _, s := range scopes {
		if m[s] {
			ret = append(ret, s)
		}
	}

	return ret
}

func (c *OAuth2ClientMixin) CheckRedirectURI(redirectURI string) bool {
	for i := range c.RedirectURIs {
		if c.RedirectURIs[i] == redirectURI {
			return true
		}
	}
	return false
}

func (c *OAuth2ClientMixin) CheckClientSecret(secret string) bool {
	// TODO - Must be used a security comparing method
	return c.ClientSecret == secret
}

func (c *OAuth2ClientMixin) CheckTokenEndpointAuthMethod(method string) bool {
	return c.TokenEndpointAuthMethod == method
}

func (c *OAuth2ClientMixin) CheckResponseType(responseType rfc6749.ResponseType) bool {
	for i := range c.GrantTypes {
		if rfc6749.ResponseType(c.GrantTypes[i]) == responseType {
			return true
		}
	}
	return false
}

func (c *OAuth2ClientMixin) CheckGrantType(grantType string) bool {
	for i := range c.GrantTypes {
		if c.GrantTypes[i] == grantType {
			return true
		}
	}
	return false
}
