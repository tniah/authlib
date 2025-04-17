package types

const (
	ScopeOpenID Scope = "openid"

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
)
