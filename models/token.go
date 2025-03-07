package models

import "time"

type Token interface {
	GetTokenID() string
	//SetID(id string)
	GetAccessToken() string
	//SetAccessToken(token string)
	GetRefreshToken() string
	//SetRefreshToken(token string)
	GetClientID() string
	//SetClientID(clientID string)
	GetType() string
	//SetTokenType(tokenType string)
	GetScopes() []string
	//SetScopes(scopes []string)
	GetIssuedAt() time.Time
	//SetIssuedAt(issuedAt time.Time)
	GetExpiresIn() time.Duration
	//SetExpiresIn(expiresIn time.Duration)
	GetUserID() string
	//SetUserID(userID string)
	GetData() map[string]interface{}
	GetExtraData() map[string]interface{}
}
