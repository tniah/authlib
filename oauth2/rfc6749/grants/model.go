package grants

import "time"

type OAuthClient interface {
	GetClientID() string
	GetClientSecret() string
	IsPublic() bool
	GetDefaultRedirectURI() string
	GetAllowedScopes(scopes []string) []string
	CheckRedirectURI(redirectURI string) bool
	CheckClientSecret(secret string) bool
	CheckTokenEndpointAuthMethod(method string) bool
	CheckResponseType(responseType string) bool
	CheckGrantType(grantType string) bool
}

type AuthorizationCode interface {
	GetCode() string
	SetCode(code string)
	GetClientID() string
	SetClientID(clientID string)
	GetUserID() string
	SetUserID(userID string)
	GetRedirectURI() string
	SetRedirectURI(redirectURI string)
	GetResponseType() string
	SetResponseType(responseType string)
	GetScopes() []string
	SetScopes(scopes []string)
	GetNonce() string
	SetNonce(nonce string)
	GetAuthTime() time.Time
	SetAuthTime(authTime time.Time)
	GetCodeChallenge() string
	SetCodeChallenge(codeChallenge string)
	GetCodeChallengeMethod() string
	SetCodeChallengeMethod(codeChallengeMethod string)
}
