package types

type ClientAuthMethod string

func NewClientAuthMethod(method string) ClientAuthMethod {
	return ClientAuthMethod(method)
}

func (m ClientAuthMethod) IsBasicAuthentication() bool {
	return m == ClientBasicAuthentication
}

func (m ClientAuthMethod) IsPostAuthentication() bool {
	return m == ClientPostAuthentication
}

func (m ClientAuthMethod) IsNoneAuthentication() bool {
	return m == ClientNoneAuthentication
}

func (m ClientAuthMethod) String() string {
	return string(m)
}
