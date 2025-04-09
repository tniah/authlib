package rfc6750

import (
	"errors"
	"time"
)

const (
	TokenTypeBearer              = "Bearer"
	DefaultAccessTokenExpiresIn  = time.Minute * 60
	AccessTokenLength            = 48
	DefaultRefreshTokenExpiresIn = time.Minute * 60 * 24
	RefreshTokenLength           = 48
)

var (
	ErrNilAccessTokenGenerator  = errors.New("access token generator is nil")
	ErrNilRefreshTokenGenerator = errors.New("refresh token generator is nil")
	ErrNilExpiresInGenerator    = errors.New("expires in generator is nil")
	ErrNilRandStringGenerator   = errors.New("random string generator is nil")
	ErrInvalidExpiresIn         = errors.New("invalid \"expiresIn\" value")
)
