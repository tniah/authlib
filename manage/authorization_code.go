package manage

import (
	"context"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"time"
)

const AuthorizationCodeLength = 48

type (
	AuthorizationCodeManager struct {
		store         AuthorizationCodeStore
		codeGenerator CodeGenerator
	}

	AuthorizationCodeStore interface {
		FetchByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
		Save(ctx context.Context, authorizationCode models.AuthorizationCode) error
		DeleteByCode(ctx context.Context, code string) error
	}

	CodeGenerator                  func(grantType string, client models.Client) (string, error)
	AuthorizationCodeManagerOption func(m *AuthorizationCodeManager)
)

func NewAuthorizationManager(store AuthorizationCodeStore, opts ...AuthorizationCodeManagerOption) *AuthorizationCodeManager {
	m := &AuthorizationCodeManager{store: store}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithCodeGenerator(fn CodeGenerator) AuthorizationCodeManagerOption {
	return func(m *AuthorizationCodeManager) {
		m.codeGenerator = fn
	}
}

func (m *AuthorizationCodeManager) QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error) {
	return m.store.FetchByCode(ctx, code)
}

func (m *AuthorizationCodeManager) Generate(grantType string, r *requests.AuthorizationRequest) (models.AuthorizationCode, error) {
	code, err := m.generateCode(grantType, r)
	if err != nil {
		return nil, err
	}

	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            r.ClientID,
		UserID:              r.UserID,
		RedirectURI:         r.RedirectURI,
		ResponseType:        r.ResponseType,
		Scopes:              r.Scopes,
		Nonce:               r.Nonce,
		State:               r.State,
		AuthTime:            time.Now().UTC().Round(time.Second),
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
	}
	if err = m.store.Save(r.Request.Context(), authCode); err != nil {
		return nil, err
	}

	return authCode, nil
}

func (m *AuthorizationCodeManager) DeleteByCode(ctx context.Context, code string) error {
	return m.store.DeleteByCode(ctx, code)
}

func (m *AuthorizationCodeManager) generateCode(grantType string, r *requests.AuthorizationRequest) (string, error) {
	if m.codeGenerator != nil {
		return m.codeGenerator(grantType, r.Client)
	}

	return common.GenerateRandString(AuthorizationCodeLength, common.AlphaNum)
}
