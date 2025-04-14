package rfc9068

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
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

func (g *JWTAccessTokenGenerator) Generate(
	grantType string,
	token models.Token,
	client models.Client,
	user models.User,
	scopes []string,
) error {
	clientID := client.GetClientID()
	token.SetClientID(clientID)

	sub := user.GetSubjectID()
	token.SetUserID(sub)

	allowedScopes := client.GetAllowedScopes(scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now()
	token.SetIssuedAt(issuedAt)

	expiresIn, err := g.expiresInHandler(grantType, client)
	if err != nil {
		return err
	}
	token.SetAccessTokenExpiresIn(expiresIn)

	jwtID := token.GetJwtID()
	if jwtID == "" {
		jwtID, err = g.jwtIDHandler(grantType, client)
		if err != nil {
			return err
		}
		token.SetJwtID(jwtID)
	}

	iss, err := g.issuerHandler(grantType, client)
	if err != nil {
		return err
	}

	claims := common.JWTClaim{
		ClaimIssuer:         iss,
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

	if fn := g.extraClaimGenerator; fn != nil {
		extraClaims, err := fn(grantType, client, user, allowedScopes)
		if err != nil {
			return err
		}

		for k, v := range extraClaims {
			claims[k] = v
		}
	}

	signingKey, signingMethod, signingKeyID, err := g.signingKeyHandler(grantType, client)
	if err != nil {
		return err
	}

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

func (g *JWTAccessTokenGenerator) issuerHandler(grantType string, client models.Client) (string, error) {
	if fn := g.issuerGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.issuer, nil
}

func (g *JWTAccessTokenGenerator) expiresInHandler(grantType string, client models.Client) (time.Duration, error) {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.expiresIn, nil
}

func (g *JWTAccessTokenGenerator) signingKeyHandler(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error) {
	if fn := g.signingKeyGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.signingKey, g.signingKeyMethod, g.signingKeyID, nil
}

func (g *JWTAccessTokenGenerator) jwtIDHandler(grantType string, client models.Client) (string, error) {
	if fn := g.jwtIDGenerator; fn != nil {
		return fn(grantType, client)
	}

	return strings.Replace(uuid.NewString(), "-", "", -1), nil
}
