package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/oauth2/rfc6749/grants"
	"time"
)

const AuthorizationCodeLength = 48

var ErrAuthorizationCodeNotFound = errors.New("authorization code not found")

type AuthorizationCodeManager struct {
	store         AuthorizationCodeStore
	codeGenerator CodeGenerator
}

type AuthorizationCodeStore interface {
	FetchByCode(ctx context.Context, code string) (grants.AuthorizationCode, error)
	Create(ctx context.Context, authCode grants.AuthorizationCode) error
	DeleteByCode(ctx context.Context, code string) error
}

type CodeGenerator func(gt grants.GrantType, r grants.AuthorizationRequest) (string, error)

type AuthCodeManagerOption func(m *AuthorizationCodeManager)

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

func (m *AuthorizationCodeManager) QueryByCode(ctx context.Context, code string) (grants.AuthorizationCode, error) {
	authCode, err := m.store.FetchByCode(ctx, code)
	if err != nil {
		return nil, err
	}

	if authCode == nil {
		return nil, ErrAuthorizationCodeNotFound
	}

	return authCode, nil
}

func (m *AuthorizationCodeManager) Save(ctx context.Context, authCode grants.AuthorizationCode) error {
	return m.store.Create(ctx, authCode)
}

func (m *AuthorizationCodeManager) DeleteByCode(ctx context.Context, code string) error {
	return m.store.DeleteByCode(ctx, code)
}

func (m *AuthorizationCodeManager) Generate(gt grants.GrantType, r grants.AuthorizationRequest) (grants.AuthorizationCode, error) {
	code, err := m.generateCode(gt, r)
	if err != nil {
		return nil, err
	}

	authCode := &models.AuthorizationCode{
		Code:         code,
		ClientID:     r.ClientID(),
		UserID:       r.UserID(),
		RedirectURI:  r.RedirectURI(),
		ResponseType: r.ResponseType(),
		Scopes:       r.Scopes(),
		State:        r.State(),
		AuthTime:     time.Now().UTC().Round(time.Second),
	}

	if err = m.store.Create(r.Request().Context(), authCode); err != nil {
		return nil, err
	}

	return authCode, nil
}

func (m *AuthorizationCodeManager) generateCode(gt grants.GrantType, r grants.AuthorizationRequest) (string, error) {
	if m.codeGenerator != nil {
		return m.codeGenerator(gt, r)
	}

	return common.GenerateRandString(AuthorizationCodeLength, common.AlphaNum)
}
