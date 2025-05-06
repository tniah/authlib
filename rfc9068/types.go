package rfc9068

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
	"time"
)

type IssuerGenerator func(ctx context.Context, client models.Client) string

type ExpiresInGenerator func(ctx context.Context, grantType string, client models.Client) time.Duration

type SigningKeyGenerator func(ctx context.Context, client models.Client) ([]byte, jwt.SigningMethod, string, error)

type ExtraClaimGenerator func(ctx context.Context, grantType string, client models.Client, user models.User, scopes types.Scopes) (map[string]interface{}, error)

type JWTIDGenerator func(ctx context.Context, grantType string, client models.Client) string
