package models

import "time"

type Token interface {
	GetTokenID() string
	GetAccessToken() string
	GetRefreshToken() string
	GetClientID() string
	GetType() string
	GetScopes() []string
	GetIssuedAt() time.Time
	GetExpiresIn() time.Duration
	GetUserID() string
	GetData() map[string]interface{}
	GetExtraData() map[string]interface{}
}
