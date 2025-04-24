package rfc6750

import (
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/utils"
	"time"
)

type OpaqueAccessTokenGenerator struct {
	*TokenGeneratorOptions
}

func NewOpaqueAccessTokenGenerator(opts ...*TokenGeneratorOptions) *OpaqueAccessTokenGenerator {
	if len(opts) > 0 {
		return &OpaqueAccessTokenGenerator{opts[0]}
	}

	defaultOpts := NewTokenGeneratorOptions()
	return &OpaqueAccessTokenGenerator{defaultOpts}
}

func (g *OpaqueAccessTokenGenerator) Generate(token models.Token, r *requests.TokenRequest) error {
	client := r.Client
	user := r.User

	token.SetClientID(client.GetClientID())
	token.SetUserID(user.GetUserID())

	allowedScopes := client.GetAllowedScopes(r.Scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now().UTC().Round(time.Second)
	token.SetIssuedAt(issuedAt)

	expiresIn := g.expiresInHandler(r.GrantType.String(), client)
	token.SetAccessTokenExpiresIn(expiresIn)

	opaqueToken := g.genToken(r.GrantType.String(), client)
	token.SetAccessToken(opaqueToken)
	return nil
}

func (g *OpaqueAccessTokenGenerator) expiresInHandler(grantType string, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.expiresIn
}

func (g *OpaqueAccessTokenGenerator) genToken(grantType string, c models.Client) string {
	if fn := g.randStringGenerator; fn != nil {
		return fn(grantType, c)
	}

	randStr, _ := utils.GenerateRandString(g.tokenLength, utils.SecretCharset)
	return randStr
}
