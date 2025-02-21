package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/oauth2/rfc6749"
)

const AuthorizationCodeLength = 48

var ErrAuthorizationCodeNotFound = errors.New("authorization code not found")

type (
	AuthorizationCodeManager struct {
		store         AuthorizationCodeStore
		codeGenerator CodeGenerator
	}
	AuthorizationCodeStore interface {
		FetchByCode(ctx context.Context, code string) (rfc6749.AuthorizationCode, error)
		Create(ctx context.Context, authCode rfc6749.AuthorizationCodeRequest) error
		DeleteByCode(ctx context.Context, code string) error
	}
	CodeGenerator         func(gt rfc6749.GrantType, client rfc6749.OAuthClient, userID string) string
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

func (m *AuthorizationCodeManager) QueryByCode(ctx context.Context, code string) (rfc6749.AuthorizationCode, error) {
	authCode, err := m.store.FetchByCode(ctx, code)
	if err != nil {
		return nil, err
	}

	if authCode == nil {
		return nil, ErrAuthorizationCodeNotFound
	}

	return authCode, nil
}

func (m *AuthorizationCodeManager) Generate(gt rfc6749.GrantType, client rfc6749.OAuthClient, userID string) string {
	if m.codeGenerator != nil {
		return m.codeGenerator(gt, client, userID)
	}

	code, _ := common.GenerateRandString(AuthorizationCodeLength, common.AlphaNum)
	return code
}

func (m *AuthorizationCodeManager) Save(ctx context.Context, authCode rfc6749.AuthorizationCodeRequest) error {
	return m.store.Create(ctx, authCode)
}

func (m *AuthorizationCodeManager) DeleteByCode(ctx context.Context, code string) error {
	return m.store.DeleteByCode(ctx, code)
}
