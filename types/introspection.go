package types

type TokenTypeHint string

func NewTokenTypeHint(s string) TokenTypeHint {
	return TokenTypeHint(s)
}

func (t TokenTypeHint) IsEmpty() bool {
	return t == ""
}

func (t TokenTypeHint) IsAccessToken() bool {
	return t == TokenTypeHintAccessToken
}

func (t TokenTypeHint) IsRefreshToken() bool {
	return t == TokenTypeHintRefreshToken
}

func (t TokenTypeHint) IsValid() bool {
	return t.IsAccessToken() || t.IsRefreshToken()
}

func (t TokenTypeHint) String() string {
	return string(t)
}
