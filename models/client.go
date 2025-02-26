package models

type OAuth2Client struct {
	ClientID                string   `json:"clientId,omitempty"`
	ClientSecret            string   `json:"clientSecret,omitempty"`
	ClientName              string   `json:"clientName,omitempty"`
	RedirectURIs            []string `json:"redirectUris,omitempty"`
	ResponseTypes           []string `json:"responseTypes,omitempty"`
	GrantTypes              []string `json:"grantTypes,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	ClientURI               string   `json:"clientUri,omitempty"`
	LogoURI                 string   `json:"logoUri,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TokenEndpointAuthMethod string   `json:"tokenEndpointAuthMethod,omitempty"`
	TosURI                  string   `json:"tosUri,omitempty"`
	PolicyURI               string   `json:"policyUri,omitempty"`
	JwksURI                 string   `json:"jwksUri,omitempty"`
	SoftwareID              string   `json:"softwareId,omitempty"`
	SoftwareVersion         string   `json:"softwareVersion,omitempty"`
}

func (c *OAuth2Client) GetClientID() string {
	return c.ClientID
}

func (c *OAuth2Client) GetClientSecret() string {
	return c.ClientSecret
}

//func (c *OAuth2Client) IsPublic() bool {
//	return c.TokenEndpointAuthMethod == "none"
//}

func (c *OAuth2Client) GetDefaultRedirectURI() string {
	if len(c.RedirectURIs) == 0 {
		return ""
	}

	return c.RedirectURIs[0]
}

func (c *OAuth2Client) GetAllowedScopes(scopes []string) []string {
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

func (c *OAuth2Client) CheckRedirectURI(redirectURI string) bool {
	for i := range c.RedirectURIs {
		if c.RedirectURIs[i] == redirectURI {
			return true
		}
	}
	return false
}

func (c *OAuth2Client) CheckClientSecret(secret string) bool {
	// TODO - Must be used a security comparing method
	return c.ClientSecret == secret
}

func (c *OAuth2Client) CheckTokenEndpointAuthMethod(method string) bool {
	return c.TokenEndpointAuthMethod == method
}

func (c *OAuth2Client) CheckResponseType(responseType string) bool {
	for i := range c.ResponseTypes {
		if c.ResponseTypes[i] == responseType {
			return true
		}
	}
	return false
}

func (c *OAuth2Client) CheckGrantType(grantType string) bool {
	for i := range c.GrantTypes {
		if c.GrantTypes[i] == grantType {
			return true
		}
	}
	return false
}
