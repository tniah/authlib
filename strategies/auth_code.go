package strategies

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

var ErrNilPointerAuthorizationCode = errors.New("authorization code is a nil pointer")

type (
	AuthCodeStrategy struct {
		store              AuthCodeStore
		codeGenerator      CodeGenerator
		expiresIn          time.Duration
		extraDataGenerator ExtraDataGenerator
	}

	AuthCodeStore interface {
		New(ctx context.Context) models.AuthorizationCode
		Save(ctx context.Context, authorizationCode models.AuthorizationCode) error
	}

	CodeGenerator          func(grantType string, client models.Client) (string, error)
	ExtraDataGenerator     func(grantType string, client models.Client, r *http.Request) (map[string]interface{}, error)
	AuthCodeStrategyOption func(m *AuthCodeStrategy)
)

func NewAuthCodeStrategy(store AuthCodeStore, opts ...AuthCodeStrategyOption) *AuthCodeStrategy {
	m := &AuthCodeStrategy{
		store:     store,
		expiresIn: DefaultExpiresIn,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

func WithCodeGenerator(fn CodeGenerator) AuthCodeStrategyOption {
	return func(m *AuthCodeStrategy) {
		m.codeGenerator = fn
	}
}

func WithExpiresIn(exp time.Duration) AuthCodeStrategyOption {
	return func(m *AuthCodeStrategy) {
		m.expiresIn = exp
	}
}

func WithExtraDataGenerator(fn ExtraDataGenerator) AuthCodeStrategyOption {
	return func(m *AuthCodeStrategy) {
		m.extraDataGenerator = fn
	}
}

func (m *AuthCodeStrategy) Generate(grantType string, r *requests.AuthorizationRequest) (models.AuthorizationCode, error) {
	code, err := m.generateCode(grantType, r)
	if err != nil {
		return nil, err
	}

	authCode := m.store.New(r.Request.Context())
	if authCode == nil {
		return nil, ErrNilPointerAuthorizationCode
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

func (m *AuthCodeStrategy) generateCode(grantType string, r *requests.AuthorizationRequest) (string, error) {
	if fn := m.codeGenerator; fn != nil {
		return fn(grantType, r.Client)
	}

	return common.GenerateRandString(AuthorizationCodeLength, common.AlphaNum)
}
