package rfc9068

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"net/http"
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
	cfg *GeneratorOptions
}

func NewJWTAccessTokenGenerator(opts *GeneratorOptions) *JWTAccessTokenGenerator {
	return &JWTAccessTokenGenerator{cfg: opts}
}

func MustJWTAccessTokenGenerator(opts *GeneratorOptions) (*JWTAccessTokenGenerator, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	return NewJWTAccessTokenGenerator(opts), nil
}

func (g *JWTAccessTokenGenerator) Generate(
	grantType string,
	token models.Token,
	client models.Client,
	user models.User,
	scopes []string,
	r *http.Request,
) error {
	clientID := client.GetClientID()
	token.SetClientID(clientID)

	sub := user.GetSubjectID()
	token.SetUserID(sub)

	allowedScopes := client.GetAllowedScopes(scopes)
	token.SetScopes(allowedScopes)

	issuedAt := time.Now()
	token.SetIssuedAt(issuedAt)

	expiresIn, err := g.expiresIn(grantType, client)
	if err != nil {
		return err
	}
	token.SetAccessTokenExpiresIn(expiresIn)

	jwtID := token.GetJwtID()
	if jwtID == "" {
		jwtID, err = g.jwtID(grantType, client)
		if err != nil {
			return err
		}
		token.SetJwtID(jwtID)
	}

	iss, err := g.issuer(grantType, client)
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

	if fn := g.cfg.extraClaimGenerator; fn != nil {
		extraClaims, err := fn(grantType, client, user, allowedScopes, r)
		if err != nil {
			return err
		}

		for k, v := range extraClaims {
			claims[k] = v
		}
	}

	signingKey, signingMethod, signingKeyID, err := g.signingKey(grantType, client)
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

func (g *JWTAccessTokenGenerator) issuer(grantType string, client models.Client) (string, error) {
	if fn := g.cfg.issuerGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.cfg.issuer, nil
}

func (g *JWTAccessTokenGenerator) expiresIn(grantType string, client models.Client) (time.Duration, error) {
	if fn := g.cfg.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.cfg.expiresIn, nil
}

func (g *JWTAccessTokenGenerator) signingKey(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error) {
	if fn := g.cfg.signingKeyGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.cfg.signingKey, g.cfg.signingKeyMethod, g.cfg.signingKeyID, nil
}

func (g *JWTAccessTokenGenerator) jwtID(grantType string, client models.Client) (string, error) {
	if fn := g.cfg.jwtIDGenerator; fn != nil {
		return fn(grantType, client)
	}

	return strings.Replace(uuid.NewString(), "-", "", -1), nil
}
