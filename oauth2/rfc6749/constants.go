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

	GtAuthorizationCode   GrantType = "authorization_code"
	GtPasswordCredentials GrantType = "password"
	GtClientCredentials   GrantType = "client_credentials"
	GtRefreshToken        GrantType = "refresh_token"
)

func (gt GrantType) String() string {
	if gt == GtAuthorizationCode ||
		gt == GtPasswordCredentials ||
		gt == GtClientCredentials ||
		gt == GtRefreshToken {
		return string(gt)
	}

	return ""
}
