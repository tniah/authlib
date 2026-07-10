package codegen

import (
	"time"

	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
)

type ExpiresInGenerator func(gt types.GrantType, client models.Client) time.Duration

type RandStringGenerator func(gt types.GrantType, client models.Client) string

type ExtraDataGenerator func(r *requests.AuthorizationRequest) (map[string]interface{}, error)
