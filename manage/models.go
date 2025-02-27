package manage

import "time"

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
	CodeChallenge       string
	CodeChallengeMethod string
}

func (c *AuthorizationCode) GetCode() string {
	return c.Code
}

func (c *AuthorizationCode) SetCode(code string) {
	c.Code = code
}

func (c *AuthorizationCode) GetClientID() string {
	return c.ClientID
}

func (c *AuthorizationCode) SetClientID(clientID string) {
	c.ClientID = clientID
}

func (c *AuthorizationCode) GetUserID() string {
	return c.UserID
}

func (c *AuthorizationCode) SetUserID(userID string) {
	c.UserID = userID
}

func (c *AuthorizationCode) GetRedirectURI() string {
	return c.RedirectURI
}

func (c *AuthorizationCode) SetRedirectURI(redirectURI string) {
	c.RedirectURI = redirectURI
}

func (c *AuthorizationCode) GetResponseType() string {
	return c.ResponseType
}

func (c *AuthorizationCode) SetResponseType(responseType string) {
	c.ResponseType = responseType
}

func (c *AuthorizationCode) GetScopes() []string {
	return c.Scopes
}

func (c *AuthorizationCode) SetScopes(scopes []string) {
	c.Scopes = scopes
}

func (c *AuthorizationCode) GetNonce() string {
	return c.Nonce
}

func (c *AuthorizationCode) SetNonce(nonce string) {
	c.Nonce = nonce
}

func (c *AuthorizationCode) GetState() string {
	return c.State
}

func (c *AuthorizationCode) SetState(state string) {
	c.State = state
}

func (c *AuthorizationCode) GetAuthTime() time.Time {
	return c.AuthTime
}

func (c *AuthorizationCode) SetAuthTime(authTime time.Time) {
	c.AuthTime = authTime
}

func (c *AuthorizationCode) GetCodeChallenge() string {
	return c.CodeChallenge
}

func (c *AuthorizationCode) SetCodeChallenge(codeChallenge string) {
	c.CodeChallenge = codeChallenge
}

func (c *AuthorizationCode) GetCodeChallengeMethod() string {
	return c.CodeChallengeMethod
}

func (c *AuthorizationCode) SetCodeChallengeMethod(codeChallengeMethod string) {
	c.CodeChallengeMethod = codeChallengeMethod
}

type Token struct {
	AccessToken  string
	RefreshToken string
	ClientID     string
	TokenType    string
	Scopes       []string
	IssuedAt     time.Time
	ExpiresIn    time.Duration
	UserID       string
}

func (t *Token) GetAccessToken() string {
	return t.AccessToken
}

func (t *Token) SetAccessToken(token string) {
	t.AccessToken = token
}

func (t *Token) GetRefreshToken() string {
	return t.RefreshToken
}

func (t *Token) SetRefreshToken(token string) {
	t.RefreshToken = token
}

func (t *Token) GetClientID() string {
	return t.ClientID
}

func (t *Token) SetClientID(clientID string) {
	t.ClientID = clientID
}

func (t *Token) GetTokenType() string {
	return t.TokenType
}

func (t *Token) SetTokenType(typ string) {
	t.TokenType = typ
}

func (t *Token) GetScopes() []string {
	return t.Scopes
}

func (t *Token) SetScopes(scopes []string) {
	t.Scopes = scopes
}

func (t *Token) GetIssuedAt() time.Time {
	return t.IssuedAt
}

func (t *Token) SetIssuedAt(issuedAt time.Time) {
	t.IssuedAt = issuedAt
}

func (t *Token) GetExpiresIn() time.Duration {
	return t.ExpiresIn
}

func (t *Token) SetExpiresIn(expiresIn time.Duration) {
	t.ExpiresIn = expiresIn
}

func (t *Token) GetUserID() string {
	return t.UserID
}

func (t *Token) SetUserID(userID string) {
	t.UserID = userID
}
