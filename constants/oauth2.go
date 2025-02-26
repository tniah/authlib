package constants

type GrantType string

type ResponseType string

type TokenEndpointAuthMethodType string

const (
	GrantTypeAuthorizationCode GrantType                   = "authorization_code"
	ResponseTypeCode           ResponseType                = "code"
	ClientSecretBasic          TokenEndpointAuthMethodType = "client_secret_basic"
	ClientSecretPost           TokenEndpointAuthMethodType = "client_secret_post"
	None                       TokenEndpointAuthMethodType = "none"

	QueryParamCode                = "code"
	QueryParamResponseType        = "response_type"
	QueryParamClientID            = "client_id"
	QueryParamRedirectURI         = "redirect_uri"
	QueryParamScope               = "scope"
	QueryParamState               = "state"
	QueryParamNonce               = "nonce"
	QueryParamCodeChallenge       = "code_challenge"
	QueryParamCodeChallengeMethod = "code_challenge_method"
	ParamClientID                 = "client_id"
	ParamClientSecret             = "client_secret"
)
