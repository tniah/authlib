package rfc6750

import (
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"time"
)

type ExpiresInGenerator func(grantType string, client models.Client) time.Duration

type RandStringGenerator func(grantType string, client models.Client) string

type TokenGenerator interface {
	Generate(token models.Token, r *requests.TokenRequest) error
}
