package rfc6750

import (
	"github.com/tniah/authlib/models"
	"net/http"
	"time"
)

type (
	AccessTokenGenerator interface {
		Generate(grantType string, token models.Token, client models.Client, user models.User, scopes []string, r *http.Request) error
	}

	RefreshTokenGenerator interface {
		Generate(grantType string, token models.Token, client models.Client, user models.User) error
	}

	ExpiresInGenerator func(grantType string, client models.Client) (time.Duration, error)

	RandStringGenerator func() (string, error)

	ExtraClaimGenerator func(grantType string, client models.Client, user models.User, scopes []string, r *http.Request) (map[string]interface{}, error)
)
