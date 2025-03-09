package rfc9068

import (
	"strings"
	"time"
)

type Token struct {
	tokenID               string
	accessToken           string
	refreshToken          string
	clientID              string
	scopes                []string
	issuedAt              time.Time
	accessTokenExpiresIn  time.Duration
	refreshTokenExpiresIn time.Duration
	userID                string
	extraData             map[string]interface{}
}

func (t *Token) GetID() string {
	return t.tokenID
}

func (t *Token) GetAccessToken() string {
	return t.accessToken
}

func (t *Token) GetRefreshToken() string {
	return t.refreshToken
}

func (t *Token) GetClientID() string {
	return t.clientID
}

func (t *Token) GetType() string {
	return TokenTypeBearer
}

func (t *Token) GetScopes() []string {
	return t.scopes
}

func (t *Token) GetIssuedAt() time.Time {
	return t.issuedAt
}

func (t *Token) GetAccessTokenExpiresIn() time.Duration {
	return t.accessTokenExpiresIn
}

func (t *Token) GetRefreshTokenExpiresIn() time.Duration {
	return t.refreshTokenExpiresIn
}

func (t *Token) GetUserID() string {
	return t.userID
}

func (t *Token) GetExtraData() map[string]interface{} {
	return t.extraData
}

func (t *Token) GetData() map[string]interface{} {
	data := map[string]interface{}{
		ParamTokenType:   TokenTypeBearer,
		ParamAccessToken: t.accessToken,
		ParamExpiresIn:   t.accessTokenExpiresIn.Seconds(),
	}

	if t.refreshToken != "" {
		data[ParamRefreshToken] = t.refreshToken
	}

	if t.scopes != nil {
		data[ParamScope] = strings.Join(t.scopes, " ")
	}

	for k, v := range t.extraData {
		data[k] = v
	}

	return data
}
