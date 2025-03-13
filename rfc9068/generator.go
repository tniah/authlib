package rfc9068

import (
	"errors"
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

var (
	ErrMissingIssuer        = errors.New("missing issuer")
	ErrInvalidExpiresIn     = errors.New("invalid 'expiresIn' value")
	ErrMissingSigningKey    = errors.New("missing signing key")
	ErrMissingSigningMethod = errors.New("missing signing method")
)

type (
	JWTAccessTokenGenerator struct {
		issuer              string
		issuerGenerator     IssuerGenerator
		expiresIn           time.Duration
		expiresInGenerator  ExpiresInGenerator
		signingKey          []byte
		signingKeyMethod    jwt.SigningMethod
		signingKeyID        string
		signingKeyGenerator SigningKeyGenerator
		extraClaimGenerator ExtraClaimGenerator
		jwtIDGenerator      JWTIDGenerator
	}

	IssuerGenerator               func(grantType string, client models.Client) (string, error)
	ExpiresInGenerator            func(grantType string, client models.Client) (time.Duration, error)
	SigningKeyGenerator           func(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error)
	ExtraClaimGenerator           func(grantType string, user models.User, client models.Client, scopes []string) (map[string]interface{}, error)
	JWTIDGenerator                func(grantType string, client models.Client) (string, error)
	JWTAccessTokenGeneratorOption func(*JWTAccessTokenGenerator)
)

func NewJWTAccessTokenGenerator() *JWTAccessTokenGenerator {
	return &JWTAccessTokenGenerator{
		expiresIn: DefaultExpiresIn,
	}
}

func WithIssuer(iss string) JWTAccessTokenGeneratorOption {
	return func(g *JWTAccessTokenGenerator) {
		g.issuer = iss
	}
}

func WithIssuerGenerator(fn IssuerGenerator) JWTAccessTokenGeneratorOption {
	return func(g *JWTAccessTokenGenerator) {
		g.issuerGenerator = fn
	}
}

func WithExpiresIn(exp time.Duration) JWTAccessTokenGeneratorOption {
	return func(g *JWTAccessTokenGenerator) {
		g.expiresIn = exp
	}
}

func WithExpiresInGenerator(fn ExpiresInGenerator) JWTAccessTokenGeneratorOption {
	return func(g *JWTAccessTokenGenerator) {
		g.expiresInGenerator = fn
	}
}

func WithSigningKey(key []byte, method jwt.SigningMethod, id ...string) JWTAccessTokenGeneratorOption {
	return func(g *JWTAccessTokenGenerator) {
		g.signingKey = key
		g.signingKeyMethod = method
		if len(id) > 0 {
			g.signingKeyID = id[0]
		}
	}
}

func WithSigningKeyGenerator(fn SigningKeyGenerator) JWTAccessTokenGeneratorOption {
	return func(g *JWTAccessTokenGenerator) {
		g.signingKeyGenerator = fn
	}
}

func WithExtraClaimGenerator(fn ExtraClaimGenerator) JWTAccessTokenGeneratorOption {
	return func(g *JWTAccessTokenGenerator) {
		g.extraClaimGenerator = fn
	}
}

func WithJWTIDGenerator(fn JWTIDGenerator) JWTAccessTokenGeneratorOption {
	return func(g *JWTAccessTokenGenerator) {
		g.jwtIDGenerator = fn
	}
}

func (g *JWTAccessTokenGenerator) Generate(
	grantType string,
	token models.Token,
	user models.User,
	client models.Client,
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

	expiresIn, err := g.getExpiresIn(grantType, client)
	if err != nil {
		return err
	}
	token.SetAccessTokenExpiresIn(expiresIn)

	jwtID := token.GetJwtID()
	if jwtID == "" {
		jwtID, err = g.generateJWTID(grantType, client)
		if err != nil {
			return err
		}
		token.SetJwtID(jwtID)
	}

	claims := common.JWTClaim{
		ClaimIssuer:         g.issuer,
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

	if g.extraClaimGenerator != nil {
		extraClaims, err := g.extraClaimGenerator(grantType, user, client, allowedScopes)
		if err != nil {
			return err
		}

		for k, v := range extraClaims {
			claims[k] = v
		}
	}

	signingKey, signingMethod, signingKeyID, err := g.getSigningKey(grantType, client)
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

func (g *JWTAccessTokenGenerator) getIssuer(grantType string, client models.Client) (string, error) {
	if fn := g.issuerGenerator; fn != nil {
		return fn(grantType, client)
	}

	if g.issuer == "" {
		return "", ErrMissingIssuer
	}

	return g.issuer, nil
}

func (g *JWTAccessTokenGenerator) getExpiresIn(grantType string, client models.Client) (time.Duration, error) {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	if g.expiresIn <= 0 {
		return 0, ErrInvalidExpiresIn
	}

	return g.expiresIn, nil
}

func (g *JWTAccessTokenGenerator) getSigningKey(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error) {
	if fn := g.signingKeyGenerator; fn != nil {
		return fn(grantType, client)
	}

	if g.signingKey == nil {
		return nil, nil, "", ErrMissingSigningKey
	}

	if g.signingKeyMethod == nil {
		return nil, nil, "", ErrMissingSigningMethod
	}

	return g.signingKey, g.signingKeyMethod, g.signingKeyID, nil
}

func (g *JWTAccessTokenGenerator) generateJWTID(grantType string, client models.Client) (string, error) {
	if fn := g.jwtIDGenerator; fn != nil {
		return fn(grantType, client)
	}

	return strings.Replace(uuid.NewString(), "-", "", -1), nil
}
