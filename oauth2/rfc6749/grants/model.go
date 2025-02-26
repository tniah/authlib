package grants

type OAuthClient interface {
	//GetClientID() string
	//GetClientSecret() string
	//IsPublic() bool
	GetDefaultRedirectURI() string
	CheckRedirectURI(RedirectURI string) bool
	//GetAllowedScopes(scopes []string) []string
	//CheckClientSecret(secret string) bool
	//CheckTokenEndpointAuthMethod(method string) bool
	CheckResponseType(responseType string) bool
	//CheckGrantType(grantType string) bool
}

type AuthorizationCode interface {
	GetCode() string
	//SetCode(code string)
	//GetClientID() string
	//SetClientID(ClientID string)
	//GetUserID() string
	//SetUserID(UserID string)
	//GetRedirectURI() string
	//SetRedirectURI(RedirectURI string)
	//GetResponseType() string
	//SetResponseType(responseType string)
	//GetScopes() []string
	//SetScopes(scopes []string)
	//GetNonce() string
	//SetNonce(nonce string)
	//GetState() string
	//SetState(state string)
	//GetAuthTime() time.Time
	//SetAuthTime(authTime time.Time)
	//GetCodeChallenge() string
	//SetCodeChallenge(codeChallenge string)
	//GetCodeChallengeMethod() string
	//SetCodeChallengeMethod(codeChallengeMethod string)
}
