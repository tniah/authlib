package models

import "time"

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
	SetResponseType(responseType string)
	GetScopes() []string
	SetScopes(scopes []string)
	GetNonce() string
	SetNonce(nonce string)
	GetAuthTime() time.Time
	SetAuthTime(authTime time.Time)
	GetCodeChallenge() string
	SetCodeChallenge(codeChallenge string)
	GetCodeChallengeMethod() string
	SetCodeChallengeMethod(codeChallengeMethod string)
}

type AuthorizationCodeMixin struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	ResponseType        string
	Scopes              []string
	Nonce               string
	State               string
	AuthTime            time.Time
	CodeChallenge       string
	CodeChallengeMethod string
}

func NewAuthorizationCode() AuthorizationCode {
	return &AuthorizationCodeMixin{}
}

func (c *AuthorizationCodeMixin) GetCode() string {
	return c.Code
}

func (c *AuthorizationCodeMixin) SetCode(code string) {
	c.Code = code
}

func (c *AuthorizationCodeMixin) GetClientID() string {
	return c.ClientID
}

func (c *AuthorizationCodeMixin) SetClientID(clientID string) {
	c.ClientID = clientID
}

func (c *AuthorizationCodeMixin) GetUserID() string {
	return c.UserID
}

func (c *AuthorizationCodeMixin) SetUserID(userID string) {
	c.UserID = userID
}

func (c *AuthorizationCodeMixin) GetRedirectURI() string {
	return c.RedirectURI
}

func (c *AuthorizationCodeMixin) SetRedirectURI(redirectURI string) {
	c.RedirectURI = redirectURI
}

func (c *AuthorizationCodeMixin) GetResponseType() string {
	return c.ResponseType
}

func (c *AuthorizationCodeMixin) SetResponseType(responseType string) {
	c.ResponseType = responseType
}

func (c *AuthorizationCodeMixin) GetScopes() []string {
	return c.Scopes
}

func (c *AuthorizationCodeMixin) SetScopes(scopes []string) {
	c.Scopes = scopes
}

func (c *AuthorizationCodeMixin) GetNonce() string {
	return c.Nonce
}

func (c *AuthorizationCodeMixin) SetNonce(nonce string) {
	c.Nonce = nonce
}

func (c *AuthorizationCodeMixin) GetAuthTime() time.Time {
	return c.AuthTime
}

func (c *AuthorizationCodeMixin) SetAuthTime(authTime time.Time) {
	c.AuthTime = authTime
}

func (c *AuthorizationCodeMixin) GetCodeChallenge() string {
	return c.CodeChallenge
}

func (c *AuthorizationCodeMixin) SetCodeChallenge(codeChallenge string) {
	c.CodeChallenge = codeChallenge
}

func (c *AuthorizationCodeMixin) GetCodeChallengeMethod() string {
	return c.CodeChallengeMethod
}

func (c *AuthorizationCodeMixin) SetCodeChallengeMethod(codeChallengeMethod string) {
	c.CodeChallengeMethod = codeChallengeMethod
}
