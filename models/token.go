package models

import (
	"github.com/tniah/authlib/types"
	"time"
)

type Token interface {
	GetType() string
	SetType(string)
	GetAccessToken() string
	SetAccessToken(token string)
	GetRefreshToken() string
	SetRefreshToken(token string)
	GetClientID() string
	SetClientID(clientID string)
	GetScopes() types.Scopes
	SetScopes(scopes types.Scopes)
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
