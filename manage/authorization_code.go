package manage

import (
	"context"
	"errors"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"net/http"
	"time"
)

const (
	AuthorizationCodeLength = 48
	DefaultExpiresIn        = time.Minute * 5
)

var (
	ErrInvalidAuthorizationCode    = errors.New("invalid authorization code")
	ErrNilPointerAuthorizationCode = errors.New("authorization code is a nil pointer")
)

type (
	AuthorizationCodeManager struct {
		store              AuthorizationCodeStore
		codeGenerator      CodeGenerator
		expiresIn          time.Duration
		extraDataGenerator ExtraDataGenerator
	}

	AuthorizationCodeStore interface {
		New(ctx context.Context) models.AuthorizationCode
		FetchByCode(ctx context.Context, code string) (models.AuthorizationCode, error)
		Save(ctx context.Context, authorizationCode models.AuthorizationCode) error
		DeleteByCode(ctx context.Context, code string) error
	}

	CodeGenerator                  func(grantType string, client models.Client) (string, error)
	ExtraDataGenerator             func(grantType string, client models.Client, r *http.Request) (map[string]interface{}, error)
	AuthorizationCodeManagerOption func(m *AuthorizationCodeManager)
)

func NewAuthorizationManager(store AuthorizationCodeStore, opts ...AuthorizationCodeManagerOption) *AuthorizationCodeManager {
	m := &AuthorizationCodeManager{
		store:     store,
		expiresIn: DefaultExpiresIn,
	}

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

func WithExpiresIn(exp time.Duration) AuthorizationCodeManagerOption {
	return func(m *AuthorizationCodeManager) {
		m.expiresIn = exp
	}
}

func WithExtraDataGenerator(fn ExtraDataGenerator) AuthorizationCodeManagerOption {
	return func(m *AuthorizationCodeManager) {
		m.extraDataGenerator = fn
	}
}

func (m *AuthorizationCodeManager) QueryByCode(ctx context.Context, code string) (models.AuthorizationCode, error) {
	authCode, err := m.store.FetchByCode(ctx, code)
	if err != nil {
		return nil, err
	}

	if authCode == nil {
		return nil, ErrInvalidAuthorizationCode
	}

	return authCode, nil
}

func (m *AuthorizationCodeManager) Generate(grantType string, r *requests.AuthorizationRequest) (models.AuthorizationCode, error) {
	code, err := m.generateCode(grantType, r)
	if err != nil {
		return nil, err
	}

	authCode, err := m.newCode(r.Request.Context())
	if err != nil {
		return nil, err
	}

	authCode.SetCode(code)
	authCode.SetClientID(r.ClientID)
	authCode.SetUserID(r.UserID)
	authCode.SetRedirectURI(r.RedirectURI)
	authCode.SetResponseType(r.ResponseType)
	authCode.SetScopes(r.Scopes)
	authCode.SetNonce(r.Nonce)
	authCode.SetState(r.State)
	authCode.SetAuthTime(time.Now())
	authCode.SetExpiresIn(m.expiresIn)
	authCode.SetCodeChallenge(r.CodeChallenge)
	authCode.SetCodeChallengeMethod(r.CodeChallengeMethod)

	if fn := m.extraDataGenerator; fn != nil {
		data, err := fn(grantType, r.Client, r.Request)
		if err != nil {
			return nil, err
		}

		authCode.SetExtraData(data)
	}

	if err = m.store.Save(r.Request.Context(), authCode); err != nil {
		return nil, err
	}

	return authCode, nil
}

func (m *AuthorizationCodeManager) DeleteByCode(ctx context.Context, code string) error {
	return m.store.DeleteByCode(ctx, code)
}

func (m *AuthorizationCodeManager) newCode(ctx context.Context) (models.AuthorizationCode, error) {
	c := m.store.New(ctx)
	if c == nil {
		return nil, ErrNilPointerAuthorizationCode
	}

	return c, nil
}

func (m *AuthorizationCodeManager) generateCode(grantType string, r *requests.AuthorizationRequest) (string, error) {
	if m.codeGenerator != nil {
		return m.codeGenerator(grantType, r.Client)
	}

	return common.GenerateRandString(AuthorizationCodeLength, common.AlphaNum)
}
