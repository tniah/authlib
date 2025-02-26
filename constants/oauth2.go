package constants

type GrantType string

type ResponseType string

const (
	GrantTypeAuthorizationCode GrantType    = "authorization_code"
	ResponseTypeCode           ResponseType = "code"

	QueryParamCode                = "code"
	QueryParamResponseType        = "response_type"
	QueryParamClientID            = "client_id"
	QueryParamRedirectURI         = "redirect_uri"
	QueryParamScope               = "scope"
	QueryParamState               = "state"
	QueryParamNonce               = "nonce"
	QueryParamCodeChallenge       = "code_challenge"
	QueryParamCodeChallengeMethod = "code_challenge_method"
)
