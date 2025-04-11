package rfc6750

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"net/http"
	"time"
)

type OpaqueAccessTokenGenerator struct {
	expiresIn           time.Duration
	expiresInGenerator  ExpiresInGenerator
	randStringGenerator RandStringGenerator
	extraClaimGenerator ExtraClaimGenerator
}

func NewOpaqueAccessTokenGenerator() *OpaqueAccessTokenGenerator {
	return &OpaqueAccessTokenGenerator{
		expiresIn: DefaultAccessTokenExpiresIn,
	}
}

func (g *OpaqueAccessTokenGenerator) SetExpiresIn(exp time.Duration) *OpaqueAccessTokenGenerator {
	g.expiresIn = exp
	return g
}

func (g *OpaqueAccessTokenGenerator) SetExpiresInGenerator(fn ExpiresInGenerator) *OpaqueAccessTokenGenerator {
	g.expiresInGenerator = fn
	return g
}

func (g *OpaqueAccessTokenGenerator) SetRandStringGenerator(fn RandStringGenerator) *OpaqueAccessTokenGenerator {
	g.randStringGenerator = fn
	return g
}

func (g *OpaqueAccessTokenGenerator) SetExtraClaimGenerator(fn ExtraClaimGenerator) *OpaqueAccessTokenGenerator {
	g.extraClaimGenerator = fn
	return g
}

func (g *OpaqueAccessTokenGenerator) Generate(
	grantType string,
	token models.Token,
	client models.Client,
	user models.User,
	scopes []string,
	r *http.Request,
) error {
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

	if g.expiresIn <= 0 {
		return 0, ErrInvalidExpiresIn
	}

	return g.expiresIn, nil
}

func (g *OpaqueAccessTokenGenerator) generate() (string, error) {
	if fn := g.randStringGenerator; fn != nil {
		return fn()
	}

	return common.GenerateRandString(AccessTokenLength, common.SecretCharset)
}
