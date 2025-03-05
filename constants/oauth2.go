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

	ParamCode                = "code"
	ParamResponseType        = "response_type"
	ParamRedirectURI         = "redirect_uri"
	ParamScope               = "scope"
	ParamState               = "state"
	ParamNonce               = "nonce"
	ParamCodeChallenge       = "code_challenge"
	ParamCodeChallengeMethod = "code_challenge_method"
	ParamClientID            = "client_id"
	ParamClientSecret        = "client_secret"
	ParamGrantType           = "grant_type"
)
