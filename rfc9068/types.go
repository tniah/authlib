package rfc9068

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/types"
	"time"
)

type IssuerGenerator func(client models.Client) string

type ExpiresInGenerator func(grantType string, client models.Client) time.Duration

type SigningKeyGenerator func(client models.Client) ([]byte, jwt.SigningMethod, string)

type ExtraClaimGenerator func(grantType string, client models.Client, user models.User, scopes types.Scopes) (map[string]interface{}, error)

type JWTIDGenerator func(grantType string, client models.Client) string
