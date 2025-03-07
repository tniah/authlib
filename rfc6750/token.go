package rfc6750

import "time"

type Token interface {
	GetType() string
	GetAccessToken() string
	GetRefreshToken() string
	GetScopes() []string
	GetExpiresIn() time.Duration
	GetExtraData() map[string]interface{}
	GetData() map[string]interface{}
}

type token struct {
	accessToken  string
	refreshToken string
	scopes       []string
	expiresIn    time.Duration
	extraData    map[string]interface{}
}

func (t *token) GetType() string {
	return TokenTypeBearer
}

func (t *token) GetAccessToken() string {
	return t.accessToken
}

func (t *token) GetRefreshToken() string {
	return t.refreshToken
}

func (t *token) GetScopes() []string {
	return t.scopes
}

func (t *token) GetExpiresIn() time.Duration {
	return t.expiresIn
}

func (t *token) GetExtraData() map[string]interface{} {
	return t.extraData
}

func (t *token) GetData() map[string]interface{} {
	data := map[string]interface{}{
		ParamTokenType:   TokenTypeBearer,
		ParamAccessToken: t.accessToken,
		ParamExpiresIn:   t.expiresIn.Seconds(),
	}

	if t.refreshToken != "" {
		data[ParamRefreshToken] = t.refreshToken
	}

	for k, v := range t.extraData {
		data[k] = v
	}

	return data
}
