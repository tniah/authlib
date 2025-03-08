package models

import "time"

type AuthorizationCode interface {
	GetCode() string
	GetClientID() string
	GetUserID() string
	GetRedirectURI() string
	GetResponseType() string
	GetScopes() []string
	GetNonce() string
	GetState() string
	GetAuthTime() time.Time
	GetExpiresIn() time.Duration
	GetCodeChallenge() string
	GetCodeChallengeMethod() string
}
