package manager

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/tniah/authlib/integrations/sql"
	authlibmodels "github.com/tniah/authlib/models"
	authlibrequests "github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/rfc6750"
	authlibtypes "github.com/tniah/authlib/types"
)

// TokenManager manages the lifecycle of OAuth2 tokens,
// delegating persistence to a repository and token generation to a BearerTokenGenerator.
type TokenManager struct {
	lock           sync.Mutex
	byAccessToken  map[string]*sql.Token
	byRefreshToken map[string]*sql.Token
	gen            *rfc6750.BearerTokenGenerator
}

// NewTokenManager creates a new TokenManager with a default BearerTokenGenerator.
func NewTokenManager() *TokenManager {
	return &TokenManager{
		byAccessToken:  make(map[string]*sql.Token),
		byRefreshToken: make(map[string]*sql.Token),
		gen:            rfc6750.NewBearerTokenGenerator(),
	}
}

// New returns a new empty Token instance satisfying the authlib model interface.
func (m *TokenManager) New() authlibmodels.Token {
	return &sql.Token{}
}

// Generate populates the token fields using the bearer token generator.
func (m *TokenManager) Generate(token authlibmodels.Token, r *authlibrequests.TokenRequest, includeRefreshToken bool) error {
	return m.gen.Generate(token, r, includeRefreshToken)
}

// Save persists a new token.
// If the provided model is not a *sql.Token, all fields are copied via setters
// into a new instance before storing.
func (m *TokenManager) Save(ctx context.Context, token authlibmodels.Token) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	entry, ok := token.(*sql.Token)
	if !ok {
		entry = &sql.Token{}
		entry.SetType(token.GetType())
		entry.SetAccessToken(token.GetAccessToken())
		entry.SetRefreshToken(token.GetRefreshToken())
		entry.SetClientID(token.GetClientID())
		entry.SetScopes(token.GetScopes())
		entry.SetIssuedAt(token.GetIssuedAt())
		entry.SetAccessTokenExpiresIn(token.GetAccessTokenExpiresIn())
		entry.SetRefreshTokenExpiresIn(token.GetRefreshTokenExpiresIn())
		entry.SetUserID(token.GetUserID())
		entry.SetJwtID(token.GetJwtID())
		if ext, ok := token.(authlibmodels.ExtendableToken); ok {
			entry.SetExtraData(ext.GetExtraData())
		}
	}

	now := time.Now().UTC().Round(time.Second)
	entry.CreatedAt = now
	entry.UpdatedAt = now

	m.byAccessToken[entry.AccessToken] = entry
	if entry.RefreshToken != "" {
		m.byRefreshToken[entry.RefreshToken] = entry
	}

	return nil
}

// QueryByToken retrieves a token by its value and optional type hint.
// When hint is refresh_token, the refresh token index is searched first.
// Returns (nil, nil) when the token does not exist.
func (m *TokenManager) QueryByToken(ctx context.Context, token string, hint authlibtypes.TokenTypeHint) (authlibmodels.Token, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if hint.IsRefreshToken() {
		if t, ok := m.byRefreshToken[token]; ok {
			return t, nil
		}
	}

	if t, ok := m.byAccessToken[token]; ok {
		return t, nil
	}

	if !hint.IsRefreshToken() {
		if t, ok := m.byRefreshToken[token]; ok {
			return t, nil
		}
	}

	return nil, nil
}

// Inspect returns the RFC 7662 §2.2 introspection claims for an active token.
// The caller (introspection endpoint) merges these with {"active": true}; do not include it here.
func (m *TokenManager) Inspect(client authlibmodels.Client, token authlibmodels.Token) map[string]interface{} {
	data := make(map[string]interface{})

	if scopes := token.GetScopes(); len(scopes) > 0 {
		data["scope"] = strings.Join(scopes.String(), " ")
	}

	if clientID := token.GetClientID(); clientID != "" {
		data["client_id"] = clientID
		data["aud"] = clientID
	}

	if tokenType := token.GetType(); tokenType != "" {
		data["token_type"] = tokenType
	}

	if issuedAt := token.GetIssuedAt(); !issuedAt.IsZero() {
		data["iat"] = issuedAt.Unix()
		data["exp"] = issuedAt.Add(token.GetAccessTokenExpiresIn()).Unix()
	}

	if userID := token.GetUserID(); userID != "" {
		data["sub"] = userID
	}

	if jti := token.GetJwtID(); jti != "" {
		data["jti"] = jti
	}

	return data
}
