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

var ErrInvalidExpiresIn = errors.New("invalid 'expiresIn' value")
