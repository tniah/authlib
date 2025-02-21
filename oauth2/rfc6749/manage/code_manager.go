package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/oauth2/rfc6749/grants"
	"github.com/tniah/authlib/oauth2/rfc6749/models"
)

const AuthorizationCodeLength = 48

var ErrAuthorizationCodeNotFound = errors.New("authorization code not found")

type (
	AuthorizationCodeManager struct {
		store         AuthorizationCodeStore
		codeGenerator CodeGenerator
	}
	AuthorizationCodeStore interface {
		FetchByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
		Create(ctx context.Context, authCode models.AuthorizationCode) error
		DeleteByCode(ctx context.Context, code string) error
	}
	CodeGenerator         func(gt grants.GrantType, client models.OAuthClient, userID string) string
	AuthCodeManagerOption func(m *AuthorizationCodeManager)
)

func NewAuthorizationCodeManager(store AuthorizationCodeStore, opts ...AuthCodeManagerOption) *AuthorizationCodeManager {
	m := &AuthorizationCodeManager{store: store}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithCodeGenerator(fn CodeGenerator) AuthCodeManagerOption {
	return func(m *AuthorizationCodeManager) {
		m.codeGenerator = fn
	}
}

func (m *AuthorizationCodeManager) QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error) {
	authCode, err := m.store.FetchByCode(ctx, code)
	if err != nil {
		return nil, err
	}

	if authCode == nil {
		return nil, ErrAuthorizationCodeNotFound
	}

	return authCode, nil
}

func (m *AuthorizationCodeManager) Save(ctx context.Context, authCode models.AuthorizationCode) error {
	return m.store.Create(ctx, authCode)
}

func (m *AuthorizationCodeManager) DeleteByCode(ctx context.Context, code string) error {
	return m.store.DeleteByCode(ctx, code)
}

func (m *AuthorizationCodeManager) Generate(gt grants.GrantType, client models.OAuthClient, userID string) models.AuthorizationCode {
	switch gt {
	case grants.GrantTypeAuthorizationCode:
		var code string
		if m.codeGenerator != nil {
			code = m.codeGenerator(gt, client, userID)
		} else {
			code, _ = common.GenerateRandString(AuthorizationCodeLength, common.AlphaNum)
		}

		authCode := models.NewAuthorizationCode()
		authCode.SetCode(code)
		// TODO - Continue to set more attributes
		return authCode
	default:
		// TODO
		return nil
	}
}
