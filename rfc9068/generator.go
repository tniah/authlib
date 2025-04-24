package rfc9068

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/utils"
	"strings"
	"time"
)

var ErrNilClient = errors.New("client is nil")

type JWTAccessTokenGenerator struct {
	*GeneratorConfig
}

func NewJWTAccessTokenGenerator(cfg *GeneratorConfig) *JWTAccessTokenGenerator {
	return &JWTAccessTokenGenerator{cfg}
}

func MustJWTAccessTokenGenerator(cfg *GeneratorConfig) (*JWTAccessTokenGenerator, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return NewJWTAccessTokenGenerator(cfg), nil
}

func (g *JWTAccessTokenGenerator) Generate(token models.Token, r *requests.TokenRequest) error {
	client := r.Client
	if client == nil {
		return ErrNilClient
	}

	clientID := client.GetClientID()
	token.SetClientID(clientID)

	sub := ""
	if user := r.User; user != nil {
		sub = user.GetUserID()
	}
	token.SetUserID(sub)

	allowedScopes := client.GetAllowedScopes(r.Scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now()
	token.SetIssuedAt(issuedAt)

	expiresIn := g.expiresInHandler(r.GrantType.String(), client)
	token.SetAccessTokenExpiresIn(expiresIn)

	jwtID := token.GetJwtID()
	if jwtID == "" {
		jwtID = g.jwtIDHandler(r.GrantType.String(), client)
		token.SetJwtID(jwtID)
	}

	claims := utils.JWTClaim{
		"iss":       g.issuerHandler(client),
		"exp":       jwt.NewNumericDate(issuedAt.Add(expiresIn)),
		"aud":       clientID,
		"client_id": clientID,
		"iat":       jwt.NewNumericDate(issuedAt),
		"jti":       jwtID,
	}

	if sub != "" {
		claims["sub"] = sub
	} else {
		claims["sub"] = clientID
	}

	if fn := g.extraClaimGenerator; fn != nil {
		extraClaims, err := fn(r.GrantType.String(), client, r.User, allowedScopes)
		if err != nil {
			return err
		}

		for k, v := range extraClaims {
			claims[k] = v
		}
	}

	signingKey, signingMethod, signingKeyID := g.signingKeyHandler(client)
	t, err := utils.NewJWTToken(signingKey, signingMethod, signingKeyID)
	if err != nil {
		return err
	}

	jwtToken, err := t.Generate(claims, utils.JWTHeader{"typ": "at+JWT"})
	if err != nil {
		return err
	}

	token.SetAccessToken(jwtToken)
	return nil
}

func (g *JWTAccessTokenGenerator) issuerHandler(client models.Client) string {
	if fn := g.issuerGenerator; fn != nil {
		return fn(client)
	}

	return g.issuer
}

func (g *JWTAccessTokenGenerator) expiresInHandler(grantType string, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.expiresIn
}

func (g *JWTAccessTokenGenerator) signingKeyHandler(client models.Client) ([]byte, jwt.SigningMethod, string) {
	if fn := g.signingKeyGenerator; fn != nil {
		return fn(client)
	}

	return g.signingKey, g.signingKeyMethod, g.signingKeyID
}

func (g *JWTAccessTokenGenerator) jwtIDHandler(grantType string, client models.Client) string {
	if fn := g.jwtIDGenerator; fn != nil {
		return fn(grantType, client)
	}

	return strings.Replace(uuid.NewString(), "-", "", -1)
}
