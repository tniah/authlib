package manage

import (
	"time"
)

type AuthorizationCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	ResponseType        string
	Scopes              []string
	Nonce               string
	State               string
	AuthTime            time.Time
	ExpiresIn           time.Duration
	CodeChallenge       string
	CodeChallengeMethod string
	ExtraData           map[string]interface{}
}

func (c *AuthorizationCode) GetCode() string {
	return c.Code
}

func (c *AuthorizationCode) GetClientID() string {
	return c.ClientID
}

func (c *AuthorizationCode) GetUserID() string {
	return c.UserID
}

func (c *AuthorizationCode) GetRedirectURI() string {
	return c.RedirectURI
}

func (c *AuthorizationCode) GetResponseType() string {
	return c.ResponseType
}

func (c *AuthorizationCode) GetScopes() []string {
	return c.Scopes
}

func (c *AuthorizationCode) GetNonce() string {
	return c.Nonce
}

func (c *AuthorizationCode) GetState() string {
	return c.State
}

func (c *AuthorizationCode) GetAuthTime() time.Time {
	return c.AuthTime
}

func (c *AuthorizationCode) GetExpiresIn() time.Duration {
	return c.ExpiresIn
}

func (c *AuthorizationCode) GetCodeChallenge() string {
	return c.CodeChallenge
}

func (c *AuthorizationCode) GetCodeChallengeMethod() string {
	return c.CodeChallengeMethod
}

func (c *AuthorizationCode) GetExtraData() map[string]interface{} {
	return c.ExtraData
}
