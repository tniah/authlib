package types

type ClientAuthMethod string

func NewClientAuthMethod(method string) ClientAuthMethod {
	return ClientAuthMethod(method)
}

func (m ClientAuthMethod) IsBasic() bool {
	return m == ClientBasicAuthentication
}

func (m ClientAuthMethod) IsPOST() bool {
	return m == ClientPostAuthentication
}

func (m ClientAuthMethod) IsNone() bool {
	return m == ClientNoneAuthentication
}

func (m ClientAuthMethod) String() string {
	return string(m)
}
