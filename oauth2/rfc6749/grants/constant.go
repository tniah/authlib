package grants

type (
	ResponseType                string
	GrantType                   string
	TokenEndpointAuthMethodType string
)

const (
	Code  = "code"
	State = "state"

	ResponseTypeCode  ResponseType = "code"
	ResponseTypeToken ResponseType = "token"

	AuthMethodClientSecretBasic TokenEndpointAuthMethodType = "client_secret_basic"
	AuthMethodClientSecretPost  TokenEndpointAuthMethodType = "client_secret_post"
	AuthMethodNone              TokenEndpointAuthMethodType = "none"

	GrantTypeAuthorizationCode   GrantType = "authorization_code"
	GrantTypePasswordCredentials GrantType = "password"
	GrantTypeClientCredentials   GrantType = "client_credentials"
	GrantTypeRefreshToken        GrantType = "refresh_token"

	ErrDescMissingClientId     = "Missing \"client_id\" parameter in request"
	ErrDescClientIDNotFound    = "No client was found that matches \"client_id\" value"
	ErrDescMissingResponseType = "Missing \"response_type\" parameter in request"
	ErrDescMissingRedirectUri  = "Missing \"redirect_uri\" parameter in request"
	ErrDescInvalidRedirectUri  = "Redirect URI is not supported by client"
)
