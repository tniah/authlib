package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/constants"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"time"
)

const authorizationCodeLength = 48

var ErrAuthorizationCodeNotFound = errors.New("authorization code not found")

type AuthorizationCodeStore interface {
	FetchByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
	Save(ctx context.Context, authorizationCode models.AuthorizationCode) error
}

type CodeGenerator func(grantType constants.GrantType, r *requests.AuthorizationRequest) (string, error)

type AuthorizationCodeManagerOption func(m *AuthorizationCodeManager)

type AuthorizationCodeManager struct {
	store         AuthorizationCodeStore
	codeGenerator CodeGenerator
}

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
	authCode, err := m.store.FetchByCode(ctx, code)
	if err != nil {
		return nil, err
	}

	if authCode == nil {
		return nil, ErrAuthorizationCodeNotFound
	}

	return authCode, nil
}

func (m *AuthorizationCodeManager) Generate(grantType constants.GrantType, r *requests.AuthorizationRequest) (string, error) {
	code, err := m.generateCode(grantType, r)
	if err != nil {
		return "", err
	}

	// TODO scopes
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            r.ClientID,
		UserID:              r.UserID,
		RedirectURI:         r.RedirectURI,
		ResponseType:        r.ResponseType,
		Nonce:               r.Nonce,
		State:               r.State,
		AuthTime:            time.Now().UTC().Round(time.Second),
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
	}
	if err = m.store.Save(r.Request.Context(), authCode); err != nil {
		return "", err
	}

	return code, nil
}

func (m *AuthorizationCodeManager) generateCode(grantType constants.GrantType, r *requests.AuthorizationRequest) (string, error) {
	if m.codeGenerator != nil {
		return m.codeGenerator(grantType, r)
	}

	return common.GenerateRandString(authorizationCodeLength, common.AlphaNum)
}
