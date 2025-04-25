package models

import (
	"github.com/tniah/authlib/types"
	"time"
)

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
	SetResponseType(rt types.ResponseType)
	GetScopes() types.Scopes
	SetScopes(scopes types.Scopes)
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
	GetCodeChallengeMethod() types.CodeChallengeMethod
	SetCodeChallengeMethod(codeChallengeMethod types.CodeChallengeMethod)
	GetExtraData() map[string]interface{}
	SetExtraData(data map[string]interface{})
}
