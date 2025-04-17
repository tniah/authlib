package rfc6750

import (
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
)

const TokenTypeBearer = "Bearer"

type BearerTokenGenerator struct {
	*BearerTokenGeneratorOptions
}

func NewBearerTokenGenerator(opts ...*BearerTokenGeneratorOptions) *BearerTokenGenerator {
	if len(opts) > 0 {
		return &BearerTokenGenerator{opts[0]}
	}

	defaultOpts := NewBearerTokenGeneratorOptions()
	return &BearerTokenGenerator{defaultOpts}
}

func MustBearerTokenGenerator(opts *BearerTokenGeneratorOptions) (*BearerTokenGenerator, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	return NewBearerTokenGenerator(opts), nil
}

func (g *BearerTokenGenerator) Generate(token models.Token, r *requests.TokenRequest, includeRefreshToken bool) error {
	if err := g.atGen.Generate(token, r); err != nil {
		return err
	}

	if includeRefreshToken {
		if err := g.rfGen.Generate(token, r); err != nil {
			return err
		}
	}

	token.SetType(TokenTypeBearer)
	return nil
}
