package rfc9068

import "time"

const (
	TokenTypeBearer           = "Bearer"
	DefaultExpiresIn          = time.Minute * 60
	DefaultRefreshTokenLength = 48

	ParamTokenType    = "token_type"
	ParamAccessToken  = "access_token"
	ParamRefreshToken = "refresh_token"
	ParamExpiresIn    = "expires_in"
	ParamScope        = "scope"

	ClaimIssuer         = "iss"
	ClaimSubject        = "sub"
	ClaimAudience       = "aud"
	ClaimExpirationTime = "exp"
	ClaimIssuedAt       = "iat"
	ClaimJwtID          = "jti"
	ClaimScope          = "scope"
	ClaimClientID       = "client_id"

	HeaderMediaType = "typ"
	MediaType       = "at+JWT"
)
