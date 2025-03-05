package manage

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/models"
	"time"
)

const (
	TokenTypeJWT                    = "jwt"
	TokenTypeOpaque                 = "opaque"
	TokenTypeBearer                 = "bearer"
	SigningMethodRS256              = "RS256"
	SigningMethodRS384              = "RS384"
	SigningMethodRS512              = "RS512"
	SigningMethodHS256              = "HS256"
	SigningMethodHS384              = "HS384"
	SigningMethodHS512              = "HS512"
	ClaimIssuer                     = "iss"
	ClaimSubject                    = "sub"
	ClaimAudience                   = "aud"
	ClaimExpirationTime             = "exp"
	ClaimNotBefore                  = "nbf"
	ClaimIssuedAt                   = "iat"
	ClaimJwtID                      = "jti"
	DefaultAccessTokenLength        = 48
	DefaultAccessTokenType          = TokenTypeJWT
	DefaultAccessTokenSigningMethod = SigningMethodRS256
	DefaultAccessTokenExpiresIn     = time.Hour * 1
)

var (
	ErrUnsupportedTokenType     = errors.New("unsupported token type")
	ErrUnsupportedSigningMethod = errors.New("unsupported signing method")
)

type TokenStore interface {
	//FetchByAccessToken(ctx context.Context, token string) (models.Token, error)
	//FetchByRefreshToken(ctx context.Context, token string) (models.Token, error)
	Save(ctx context.Context, token models.Token) error
}

type TokenManager struct {
	store                    TokenStore
	issuer                   string
	accessTokenType          string
	accessTokenExpiresIn     time.Duration
	accessTokenSigningMethod string
	accessTokenSigningKey    []byte
	accessTokenLength        int
}

type TokenManagerOption func(*TokenManager)

func NewTokenManager(store TokenStore, opts ...TokenManagerOption) *TokenManager {
	m := &TokenManager{
		store:                    store,
		accessTokenType:          DefaultAccessTokenType,
		accessTokenSigningMethod: DefaultAccessTokenSigningMethod,
		accessTokenExpiresIn:     DefaultAccessTokenExpiresIn,
		accessTokenLength:        DefaultAccessTokenLength,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithIssuer(issuer string) TokenManagerOption {
	return func(m *TokenManager) {
		m.issuer = issuer
	}
}

func WithAccessTokenType(typ string) TokenManagerOption {
	return func(m *TokenManager) {
		m.accessTokenType = typ
	}
}

func WithAccessTokenExpiresIn(expiresIn time.Duration) TokenManagerOption {
	return func(m *TokenManager) {
		m.accessTokenExpiresIn = expiresIn
	}
}

func WithAccessTokenSigningMethod(method string) TokenManagerOption {
	return func(m *TokenManager) {
		m.accessTokenSigningMethod = method
	}
}

func WithAccessTokenSigningKey(key []byte) TokenManagerOption {
	return func(m *TokenManager) {
		m.accessTokenSigningKey = key
	}
}

func WithAccessTokenLength(l int) TokenManagerOption {
	return func(m *TokenManager) {
		m.accessTokenLength = l
	}
}

func (m *TokenManager) GenerateAccessToken(grantType constants.GrantType, user models.User, client models.Client, scopes []string) (models.Token, error) {
	typ, err := m.getAccessTokenType()
	if err != nil {
		return nil, err
	}

	var token string
	issuedAt := time.Now()
	if typ == TokenTypeOpaque {
		token, err = m.generateOpaqueToken(m.accessTokenLength)
		if err != nil {
			return nil, err
		}
	} else {
		signingMethod, err := m.getSigningMethod(m.accessTokenSigningMethod)
		if err != nil {
			return nil, err
		}

		// TODO - scopes
		claims := common.JWTClaim{
			ClaimIssuer:         m.issuer,
			ClaimSubject:        user.GetSubjectID(),
			ClaimAudience:       client.GetClientID(),
			ClaimIssuedAt:       jwt.NewNumericDate(issuedAt),
			ClaimExpirationTime: jwt.NewNumericDate(issuedAt.Add(m.accessTokenExpiresIn)),
		}
		token, err = m.generateJWTToken(m.accessTokenSigningKey, signingMethod, claims)
		if err != nil {
			return nil, err
		}
	}

	return &Token{
		AccessToken: token,
		ClientID:    client.GetClientID(),
		TokenType:   TokenTypeBearer,
		Scopes:      scopes,
		IssuedAt:    issuedAt,
		ExpiresIn:   m.accessTokenExpiresIn,
		UserID:      user.GetSubjectID(),
	}, nil
}

func (m *TokenManager) SaveAccessToken(ctx context.Context, token models.Token) error {
	return m.store.Save(ctx, token)
}

func (m *TokenManager) getAccessTokenType() (string, error) {
	if m.accessTokenType == TokenTypeJWT || m.accessTokenType == TokenTypeOpaque {
		return m.accessTokenType, nil
	}

	return "", ErrUnsupportedTokenType
}

func (m *TokenManager) generateOpaqueToken(l int) (string, error) {
	return common.GenerateRandString(l, common.AlphaNum)
}

func (m *TokenManager) generateJWTToken(signingKey []byte, signingMethod jwt.SigningMethod, claims common.JWTClaim) (string, error) {
	token, err := common.NewJWTToken(signingKey, signingMethod)
	if err != nil {
		return "", err
	}

	return token.Generate(claims, nil)
}

func (m *TokenManager) getSigningMethod(method string) (jwt.SigningMethod, error) {
	switch method {
	case SigningMethodRS256:
		return jwt.SigningMethodRS256, nil
	case SigningMethodRS384:
		return jwt.SigningMethodRS384, nil
	case SigningMethodRS512:
		return jwt.SigningMethodRS512, nil
	case SigningMethodHS256:
		return jwt.SigningMethodHS256, nil
	case SigningMethodHS384:
		return jwt.SigningMethodHS384, nil
	case SigningMethodHS512:
		return jwt.SigningMethodHS512, nil
	default:
		return nil, ErrUnsupportedSigningMethod
	}
}
