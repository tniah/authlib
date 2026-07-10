package rfc6750

import (
	"context"
	"errors"
	"time"

	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/utils"
)

var ErrNilClient = errors.New("client is nil")

// OpaqueAccessTokenGenerator generates a random opaque (non-JWT) access token.
// All fields are configurable via TokenGeneratorOptions; defaults produce a
// 48-character random string with a 60-minute expiry.
type OpaqueAccessTokenGenerator struct {
	*TokenGeneratorOptions
}

// NewOpaqueAccessTokenGenerator creates a generator with optional custom options.
// If no options are provided, defaults from NewTokenGeneratorOptions() are used.
func NewOpaqueAccessTokenGenerator(opts ...*TokenGeneratorOptions) *OpaqueAccessTokenGenerator {
	if len(opts) > 0 {
		return &OpaqueAccessTokenGenerator{opts[0]}
	}

	defaultOpts := NewTokenGeneratorOptions()
	return &OpaqueAccessTokenGenerator{defaultOpts}
}

// Generate populates token with an opaque access token derived from the request.
// User may be nil (e.g. client credentials flow); in that case UserID is left empty.
func (g *OpaqueAccessTokenGenerator) Generate(token models.Token, r *requests.TokenRequest) error {
	client := r.Client
	if client == nil {
		return ErrNilClient
	}

	// Prefer request context so custom generators can do context-aware work
	// (e.g. database lookups). Fall back to Background when called outside
	// of an HTTP request (e.g. unit tests).
	ctx := context.Background()
	if r.Request != nil {
		ctx = r.Request.Context()
	}

	token.SetClientID(client.GetClientID())

	// User is optional (absent in client credentials flows).
	if user := r.User; user != nil {
		token.SetUserID(user.GetUserID())
	}

	// Intersect requested scopes with the scopes allowed for this client.
	allowedScopes := client.GetAllowedScopes(r.Scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now().UTC().Round(time.Second)
	token.SetIssuedAt(issuedAt)

	expiresIn := g.expiresInHandler(ctx, r.GrantType.String(), client)
	token.SetAccessTokenExpiresIn(expiresIn)

	opaqueToken := g.genToken(ctx, r.GrantType.String(), client)
	token.SetAccessToken(opaqueToken)
	return nil
}

// expiresInHandler delegates to the custom ExpiresInGenerator if set,
// otherwise returns the static expiry duration from options.
func (g *OpaqueAccessTokenGenerator) expiresInHandler(ctx context.Context, grantType string, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	return g.expiresIn
}

// genToken delegates to the custom RandStringGenerator if set,
// otherwise generates a cryptographically random string of configured length.
func (g *OpaqueAccessTokenGenerator) genToken(ctx context.Context, grantType string, c models.Client) string {
	if fn := g.randStringGenerator; fn != nil {
		return fn(ctx, grantType, c)
	}

	randStr, _ := utils.GenerateRandString(g.tokenLength, utils.SecretCharset)
	return randStr
}
