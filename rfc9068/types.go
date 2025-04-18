package rfc9068

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/tniah/authlib/models"
	"time"
)

type IssuerGenerator func(client models.Client) string

type ExpiresInGenerator func(grantType string, client models.Client) time.Duration

type SigningKeyGenerator func(client models.Client) ([]byte, jwt.SigningMethod, string)

type ExtraClaimGenerator func(grantType string, client models.Client, user models.User, scopes []string) (map[string]interface{}, error)
