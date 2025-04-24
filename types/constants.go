package types

const (
	ScopeOpenID Scope = "openid"

	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeROPC              GrantType = "password"
	GrantTypeRefreshToken      GrantType = "refresh_token"

	ResponseTypeToken ResponseType = "token"
	ResponseTypeCode  ResponseType = "code"

	DisplayPage  Display = "page"
	DisplayPopup Display = "popup"
	DisplayTouch Display = "touch"
	DisplayWap   Display = "wap"

	PromptNone          Prompt = "none"
	PromptLogin         Prompt = "login"
	PromptConsent       Prompt = "consent"
	PromptSelectAccount Prompt = "select_account"

	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
	CodeChallengeMethodS256  CodeChallengeMethod = "S256"

	TokenTypeHintAccessToken  TokenTypeHint = "access_token"
	TokenTypeHintRefreshToken TokenTypeHint = "refresh_token"

	ClientBasicAuthentication ClientAuthMethod = "client_secret_basic"
	ClientPostAuthentication  ClientAuthMethod = "client_secret_post"
	ClientNoneAuthentication  ClientAuthMethod = "none"

	ContentTypeJSON               ContentType = "application/json;charset=UTF-8"
	ContentTypeXWWWFormUrlencoded ContentType = "application/x-www-form-urlencoded"
)
