package models

import "time"

type Token interface {
	GetType() string
	SetType(string)
	GetAccessToken() string
	SetAccessToken(accessToken string)
	GetRefreshToken() string
	SetRefreshToken(refreshToken string)
	GetClientID() string
	SetClientID(clientID string)
	GetScopes() []string
	SetScopes(scopes []string)
	GetIssuedAt() time.Time
	SetIssuedAt(issuedAt time.Time)
	GetAccessTokenExpiresIn() time.Duration
	SetAccessTokenExpiresIn(exp time.Duration)
	GetRefreshTokenExpiresIn() time.Duration
	SetRefreshTokenExpiresIn(exp time.Duration)
	GetUserID() string
	SetUserID(userID string)
	GetJwtID() string
	SetJwtID(id string)
}

type ExtendableToken interface {
	Token
	GetExtraData() map[string]interface{}
	SetExtraData(data map[string]interface{})
}
