package rfc6749

type (
	ResponseType                string
	GrantType                   string
	TokenEndpointAuthMethodType string
)

const (
	ResponseTypeCode  ResponseType = "code"
	ResponseTypeToken ResponseType = "token"

	AuthMethodClientSecretBasic TokenEndpointAuthMethodType = "client_secret_basic"
	AuthMethodClientSecretPost  TokenEndpointAuthMethodType = "client_secret_post"
	AuthMethodNone              TokenEndpointAuthMethodType = "none"

	GrantTypeAuthorizationCode   GrantType = "authorization_code"
	GrantTypePasswordCredentials GrantType = "password"
	GrantTypeClientCredentials   GrantType = "client_credentials"
	GrantTypeRefreshToken        GrantType = "refresh_token"
)

func (gt GrantType) String() string {
	if gt == GrantTypeAuthorizationCode ||
		gt == GrantTypePasswordCredentials ||
		gt == GrantTypeClientCredentials ||
		gt == GrantTypeRefreshToken {
		return string(gt)
	}

	return ""
}
