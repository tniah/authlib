package rfc6750

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
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

func (g *OpaqueAccessTokenGenerator) Generate(grantType string, token models.Token, client models.Client, user models.User, scopes []string) error {
	token.SetClientID(client.GetClientID())
	token.SetUserID(user.GetSubjectID())

	allowedScopes := client.GetAllowedScopes(scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now()
	token.SetIssuedAt(issuedAt)

	expiresIn, err := g.getExpiresIn(grantType, client)
	if err != nil {
		return err
	}
	token.SetAccessTokenExpiresIn(expiresIn)

	opaqueToken, err := g.generate()
	if err != nil {
		return err
	}

	token.SetAccessToken(opaqueToken)
	return nil
}

func (g *OpaqueAccessTokenGenerator) getExpiresIn(grantType string, client models.Client) (time.Duration, error) {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.expiresIn, nil
}

func (g *OpaqueAccessTokenGenerator) generate() (string, error) {
	if fn := g.randStringGenerator; fn != nil {
		return fn()
	}

	return common.GenerateRandString(g.tokenLength, common.SecretCharset)
}
