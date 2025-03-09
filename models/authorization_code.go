package models

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
	SetAuthTime(time.Time)
	GetExpiresIn() time.Duration
	SetExpiresIn(time.Duration)
	GetCodeChallenge() string
	SetCodeChallenge(codeChallenge string)
	GetCodeChallengeMethod() string
	SetCodeChallengeMethod(codeChallengeMethod string)
	GetExtraData() map[string]interface{}
	SetExtraData(data map[string]interface{})
}
