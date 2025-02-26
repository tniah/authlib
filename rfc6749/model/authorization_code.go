package model

import "time"

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
	GetState() string
	SetState(state string)
	GetAuthTime() time.Time
	SetAuthTime(authTime time.Time)
	GetCodeChallenge() string
	SetCodeChallenge(codeChallenge string)
	GetCodeChallengeMethod() string
	SetCodeChallengeMethod(codeChallengeMethod string)
}
