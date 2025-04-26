package types

type ClientAuthMethod string

func NewClientAuthMethod(method string) ClientAuthMethod {
	return ClientAuthMethod(method)
}

func (m ClientAuthMethod) Equal(o ClientAuthMethod) bool {
	return m == o
}

func (m ClientAuthMethod) IsBasic() bool {
	return m.Equal(ClientBasicAuthentication)
}

func (m ClientAuthMethod) IsPOST() bool {
	return m.Equal(ClientPostAuthentication)
}

func (m ClientAuthMethod) IsNone() bool {
	return m.Equal(ClientNoneAuthentication)
}

func (m ClientAuthMethod) IsEmpty() bool {
	return m.Equal("")
}

func (m ClientAuthMethod) String() string {
	return string(m)
}
