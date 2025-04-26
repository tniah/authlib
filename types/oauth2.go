package types

type GrantType string

func NewGrantType(s string) GrantType {
	return GrantType(s)
}

func (g GrantType) IsEmpty() bool {
	return g == ""
}

func (g GrantType) Equal(other GrantType) bool {
	return g == other
}

func (g GrantType) IsAuthorizationCode() bool {
	return g.Equal(GrantTypeAuthorizationCode)
}

func (g GrantType) IsClientCredentials() bool {
	return g.Equal(GrantTypeClientCredentials)
}

func (g GrantType) IsROPC() bool {
	return g.Equal(GrantTypeROPC)
}

func (g GrantType) IsRefreshToken() bool {
	return g.Equal(GrantTypeRefreshToken)
}

func (g GrantType) String() string {
	return string(g)
}

type GrantTypes []GrantType

func NewGrantTypes(gts []string) GrantTypes {
	ret := make(GrantTypes, len(gts))
	for i, g := range gts {
		ret[i] = NewGrantType(g)
	}
	return ret
}

func (g GrantTypes) Contains(expected GrantType) bool {
	for _, gt := range g {
		if gt.Equal(expected) {
			return true
		}
	}
	return false
}

func (g GrantTypes) String() []string {
	ret := make([]string, len(g))
	for i, gt := range g {
		ret[i] = gt.String()
	}
	return ret
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

type ResponseTypes []ResponseType

func NewResponseTypes(typ []string) ResponseTypes {
	ret := make(ResponseTypes, len(typ))
	for i, t := range typ {
		ret[i] = NewResponseType(t)
	}
	return ret
}

func (r ResponseTypes) String() []string {
	ret := make([]string, len(r))
	for i, t := range r {
		ret[i] = t.String()
	}
	return ret
}
