package types

type Scope string

func NewScope(s string) Scope {
	return Scope(s)
}

func (s Scope) IsOpenID() bool {
	return s == ScopeOpenID
}

type ResponseType string

func NewResponseType(s string) ResponseType {
	return ResponseType(s)
}

func (t ResponseType) IsCode() bool {
	return t == ResponseTypeCode
}

func (t ResponseType) IsToken() bool {
	return t == ResponseTypeToken
}

func (t ResponseType) IsValid() bool {
	return t.IsCode() || t.IsToken()
}

type Display string

func NewDisplay(s string) Display {
	return Display(s)
}

func (d Display) IsPage() bool {
	return d == DisplayPage
}

func (d Display) IsPopup() bool {
	return d == DisplayPopup
}

func (d Display) IsTouch() bool {
	return d == DisplayTouch
}

func (d Display) IsWap() bool {
	return d == DisplayWap
}

func (d Display) IsValid() bool {
	return d.IsPage() || d.IsPopup() || d.IsTouch() || d.IsWap()
}

type Prompt string

func NewPrompt(s string) Prompt {
	return Prompt(s)
}

func (p Prompt) IsNone() bool {
	return p == PromptNone
}

func (p Prompt) IsLogin() bool {
	return p == PromptLogin
}

func (p Prompt) IsConsent() bool {
	return p == PromptConsent
}

func (p Prompt) IsSelectAccount() bool {
	return p == PromptSelectAccount
}

func (p Prompt) IsValid() bool {
	return p.IsNone() || p.IsLogin() || p.IsConsent() || p.IsSelectAccount()
}
