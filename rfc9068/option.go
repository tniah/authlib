package rfc9068

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tniah/authlib/models"
	"net/http"
	"time"
)

var (
	ErrMissingIssuer           = errors.New("\"issuer\" or \"issuerGenerator\" is required")
	ErrMissingExpiresIn        = errors.New("\"expiresIn\" or \"expiresInGenerator\" is required")
	ErrMissingSigningKey       = errors.New("\"signingKey\" or \"signingKeyGenerator\" is required")
	ErrMissingSigningKeyMethod = errors.New("\"signingKeyMethod\" is required")
)

type (
	GeneratorOptions struct {
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

	IssuerGenerator func(grantType string, client models.Client) (string, error)

	ExpiresInGenerator func(grantType string, client models.Client) (time.Duration, error)

	SigningKeyGenerator func(grantType string, client models.Client) ([]byte, jwt.SigningMethod, string, error)

	ExtraClaimGenerator func(grantType string, client models.Client, user models.User, scopes []string, r *http.Request) (map[string]interface{}, error)

	JWTIDGenerator func(grantType string, client models.Client) (string, error)
)

func NewJWTAccessTokenGeneratorOptions() *GeneratorOptions {
	return &GeneratorOptions{
		expiresIn: DefaultExpiresIn,
	}
}

func (opt *GeneratorOptions) SetIssuer(iss string) *GeneratorOptions {
	opt.issuer = iss
	return opt
}

func (opt *GeneratorOptions) SetIssuerGenerator(fn IssuerGenerator) *GeneratorOptions {
	opt.issuerGenerator = fn
	return opt
}

func (opt *GeneratorOptions) SetExpiresIn(exp time.Duration) *GeneratorOptions {
	opt.expiresIn = exp
	return opt
}

func (opt *GeneratorOptions) SetExpiresInGenerator(fn ExpiresInGenerator) *GeneratorOptions {
	opt.expiresInGenerator = fn
	return opt
}

func (opt *GeneratorOptions) SetSigningKey(key []byte, method jwt.SigningMethod, id ...string) *GeneratorOptions {
	opt.signingKey = key
	opt.signingKeyMethod = method

	if len(id) > 0 {
		opt.signingKeyID = id[0]
	}

	return opt
}

func (opt *GeneratorOptions) SetSigningKeyGenerator(fn SigningKeyGenerator) *GeneratorOptions {
	opt.signingKeyGenerator = fn
	return opt
}

func (opt *GeneratorOptions) SetExtraClaimGenerator(fn ExtraClaimGenerator) *GeneratorOptions {
	opt.extraClaimGenerator = fn
	return opt
}

func (opt *GeneratorOptions) SetJWTIDGenerator(fn JWTIDGenerator) *GeneratorOptions {
	opt.jwtIDGenerator = fn
	return opt
}

func (opt *GeneratorOptions) Validate() error {
	if opt.issuer == "" && opt.issuerGenerator == nil {
		return ErrMissingIssuer
	}

	if opt.expiresIn == 0 && opt.expiresInGenerator == nil {
		return ErrMissingExpiresIn
	}

	if opt.signingKey == nil && opt.signingKeyGenerator == nil {
		return ErrMissingSigningKey
	}

	if opt.signingKey != nil && opt.signingKeyMethod == nil {
		return ErrMissingSigningKeyMethod
	}

	return nil
}
