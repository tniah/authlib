package rfc6750

import (
	"github.com/tniah/authlib/models"
	"time"
)

type (
	TokenGenerator interface {
		Generate(grantType string, token models.Token, client models.Client, user models.User, scopes []string) error
	}

	ExpiresInGenerator func(grantType string, client models.Client) (time.Duration, error)

	RandStringGenerator func() (string, error)
)
