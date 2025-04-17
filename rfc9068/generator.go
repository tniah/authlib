package rfc9068

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"strings"
	"time"
)

const (
	DefaultExpiresIn    = time.Minute * 60
	ClaimIssuer         = "iss"
	ClaimSubject        = "sub"
	ClaimAudience       = "aud"
	ClaimExpirationTime = "exp"
	ClaimIssuedAt       = "iat"
	ClaimJwtID          = "jti"
	ClaimClientID       = "client_id"
	HeaderMediaType     = "typ"
	MediaType           = "at+JWT"
)

type JWTAccessTokenGenerator struct {
	*JWTAccessTokenGeneratorConfig
}

func NewJWTAccessTokenGenerator(cfg *JWTAccessTokenGeneratorConfig) *JWTAccessTokenGenerator {
	return &JWTAccessTokenGenerator{cfg}
}

func MustJWTAccessTokenGenerator(cfg *JWTAccessTokenGeneratorConfig) (*JWTAccessTokenGenerator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return NewJWTAccessTokenGenerator(cfg), nil
}

func (g *JWTAccessTokenGenerator) Generate(token models.Token, r *requests.TokenRequest) error {
	client := r.Client
	user := r.User

	clientID := client.GetClientID()
	token.SetClientID(clientID)

	sub := user.GetSubjectID()
	token.SetUserID(sub)

	allowedScopes := client.GetAllowedScopes(r.Scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now()
	token.SetIssuedAt(issuedAt)

	expiresIn := g.expiresInHandler(r.GrantType, client)
	token.SetAccessTokenExpiresIn(expiresIn)

	jwtID := token.GetJwtID()
	if jwtID == "" {
		jwtID, err := g.jwtIDHandler(r.GrantType, client)
		if err != nil {
			return err
		}
		token.SetJwtID(jwtID)
	}

	claims := common.JWTClaim{
		ClaimIssuer:         g.issuerHandler(client),
		ClaimExpirationTime: jwt.NewNumericDate(issuedAt.Add(expiresIn)),
		ClaimAudience:       clientID,
		ClaimClientID:       clientID,
		ClaimIssuedAt:       jwt.NewNumericDate(issuedAt),
		ClaimJwtID:          jwtID,
	}

	if sub != "" {
		claims[ClaimSubject] = sub
	} else {
		claims[ClaimSubject] = clientID
	}

	if fn := g.ExtraClaimGenerator(); fn != nil {
		extraClaims, err := fn(r.GrantType, client, user, allowedScopes)
		if err != nil {
			return err
		}

		for k, v := range extraClaims {
			claims[k] = v
		}
	}

	signingKey, signingMethod, signingKeyID := g.signingKeyHandler(client)
	t, err := common.NewJWTToken(signingKey, signingMethod, signingKeyID)
	if err != nil {
		return err
	}

	jwtToken, err := t.Generate(claims, common.JWTHeader{HeaderMediaType: MediaType})
	if err != nil {
		return err
	}

	token.SetAccessToken(jwtToken)
	return nil
}

func (g *JWTAccessTokenGenerator) issuerHandler(client models.Client) string {
	if fn := g.IssuerGenerator(); fn != nil {
		return fn(client)
	}

	return g.Issuer()
}

func (g *JWTAccessTokenGenerator) expiresInHandler(grantType string, client models.Client) time.Duration {
	if fn := g.ExpiresInGenerator(); fn != nil {
		return fn(grantType, client)
	}

	return g.ExpiresIn()
}

func (g *JWTAccessTokenGenerator) signingKeyHandler(client models.Client) ([]byte, jwt.SigningMethod, string) {
	if fn := g.SigningKeyGenerator(); fn != nil {
		return fn(client)
	}

	return g.SigningKey(), g.SigningKeyMethod(), g.SigningKeyID()
}

func (g *JWTAccessTokenGenerator) jwtIDHandler(grantType string, client models.Client) (string, error) {
	if fn := g.JWTIDGenerator(); fn != nil {
		return fn(grantType, client)
	}

	return strings.Replace(uuid.NewString(), "-", "", -1), nil
}
