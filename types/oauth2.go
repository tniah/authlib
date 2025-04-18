package types

type GrantType string

func NewGrantType(s string) GrantType {
	return GrantType(s)
}

func (g GrantType) IsEmpty() bool {
	return g == ""
}

func (g GrantType) IsAuthorizationCode() bool {
	return g == GrantTypeAuthorizationCode
}

func (g GrantType) IsClientCredentials() bool {
	return g == GrantTypeClientCredentials
}

func (g GrantType) IsROPC() bool {
	return g == GrantTypeROPC
}

func (g GrantType) IsRefreshToken() bool {
	return g == GrantTypeRefreshToken
}

func (g GrantType) String() string {
	return string(g)
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

func (t ResponseType) Equal(other string) bool {
	return t == ResponseType(other)
}

func (t ResponseType) IsEmpty() bool {
	return t == ""
}

func (t ResponseType) IsValid() bool {
	return t.IsCode() || t.IsToken()
}

func (t ResponseType) String() string {
	return string(t)
}
