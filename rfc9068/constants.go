package rfc9068

import "time"

const (
	TokenTypeBearer              = "Bearer"
	DefaultAccessTokenExpiresIn  = time.Minute * 60
	DefaultRefreshTokenExpiresIn = time.Minute * 60 * 24
	DefaultRefreshTokenLength    = 48

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
