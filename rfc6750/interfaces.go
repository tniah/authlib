package rfc6750

import (
	"github.com/tniah/authlib/models"
	"time"
)

type (
	AccessTokenGenerator interface {
		Generate(grantType string, token models.Token, user models.User, client models.Client, scopes []string) error
	}

	RefreshTokenGenerator interface {
		Generate(grantType string, token models.Token, user models.User, client models.Client) error
	}

	ExpiresInGenerator func(grantType string, client models.Client) (time.Duration, error)

	RandStringGenerator func() (string, error)
)
