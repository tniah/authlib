package models

import "time"

type Token interface {
	GetID() string
	SetID(id string)
	GetAccessToken() string
	SetAccessToken(token string)
	GetRefreshToken() string
	SetRefreshToken(token string)
	GetClientID() string
	SetClientID(clientID string)
	GetTokenType() string
	SetTokenType(tokenType string)
	GetScopes() []string
	SetScopes(scopes []string)
	GetIssuedAt() time.Time
	SetIssuedAt(issuedAt time.Time)
	GetExpiresIn() time.Duration
	SetExpiresIn(expiresIn time.Duration)
	GetUserID() string
	SetUserID(userID string)
}
