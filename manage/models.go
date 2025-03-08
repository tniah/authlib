package manage

import (
	"strings"
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

type Token struct {
	TokenID      string
	AccessToken  string
	RefreshToken string
	ClientID     string
	TokenType    string
	Scopes       []string
	IssuedAt     time.Time
	ExpiresIn    time.Duration
	UserID       string
}

func (t *Token) GetTokenID() string {
	return t.TokenID
}

func (t *Token) GetAccessToken() string {
	return t.AccessToken
}

func (t *Token) GetRefreshToken() string {
	return t.RefreshToken
}

func (t *Token) GetClientID() string {
	return t.ClientID
}

func (t *Token) GetType() string {
	return t.TokenType
}

func (t *Token) GetScopes() []string {
	return t.Scopes
}

func (t *Token) GetIssuedAt() time.Time {
	return t.IssuedAt
}

func (t *Token) GetExpiresIn() time.Duration {
	return t.ExpiresIn
}

func (t *Token) GetUserID() string {
	return t.UserID
}

func (t *Token) GetData() map[string]interface{} {
	data := map[string]interface{}{
		"token_type":   t.TokenType,
		"access_token": t.AccessToken,
		"expires_in":   t.ExpiresIn.Seconds(),
	}

	if t.RefreshToken != "" {
		data["refresh_token"] = t.RefreshToken
	}

	if t.Scopes != nil {
		data["scope"] = strings.Join(t.Scopes, " ")
	}

	return data
}

func (t *Token) GetExtraData() map[string]interface{} {
	return map[string]interface{}{
		"user_id":   t.UserID,
		"client_id": t.ClientID,
	}
}
