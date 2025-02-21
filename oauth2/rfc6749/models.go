package rfc6749

type OAuthClient interface {
	//GetClientID() string
	GetDefaultRedirectUri() string
	CheckRedirectUri(redirectUri string) bool
	//GetAllowedScopes() []string

	//CheckTokenEndpointAuthMethod(method TokenEndpointAuthMethodType) bool
	CheckResponseType(responseType ResponseType) bool
	//CheckGrantType(grantType GrantType) bool
}
