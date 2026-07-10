package rfc6750

import (
	"context"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"time"
)

type ExpiresInGenerator func(ctx context.Context, grantType string, client models.Client) time.Duration

type RandStringGenerator func(ctx context.Context, grantType string, client models.Client) string

type TokenGenerator interface {
	Generate(token models.Token, r *requests.TokenRequest) error
}
