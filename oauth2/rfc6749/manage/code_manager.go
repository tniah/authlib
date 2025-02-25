package manage

//
//import (
//	"context"
//	"errors"
//	"github.com/tniah/authlib/common"
//	"github.com/tniah/authlib/models"
//	"github.com/tniah/authlib/oauth2/rfc6749"
//	"github.com/tniah/authlib/oauth2/rfc6749/grants"
//)
//
//const AuthorizationCodeLength = 48
//
//var ErrAuthorizationCodeNotFound = errors.New("authorization code not found")
//
//type (
//	AuthorizationCodeManager struct {
//		store         AuthorizationCodeStore
//		codeGenerator CodeGenerator
//	}
//	AuthorizationCodeStore interface {
//		FetchByCode(ctx context.Context, code string) (rfc6749.AuthorizationCode, error)
//		Create(ctx context.Context, authCode rfc6749.AuthorizationCode) error
//		DeleteByCode(ctx context.Context, code string) error
//	}
//	CodeGenerator         func(gt grants.GrantType, client rfc6749.OAuthClient, userID string) string
//	AuthCodeManagerOption func(m *AuthorizationCodeManager)
//)
//
//func NewAuthorizationCodeManager(store AuthorizationCodeStore, opts ...AuthCodeManagerOption) *AuthorizationCodeManager {
//	m := &AuthorizationCodeManager{store: store}
//	for _, opt := range opts {
//		opt(m)
//	}
//	return m
//}
//
//func WithCodeGenerator(fn CodeGenerator) AuthCodeManagerOption {
//	return func(m *AuthorizationCodeManager) {
//		m.codeGenerator = fn
//	}
//}
//
//func (m *AuthorizationCodeManager) QueryByCode(ctx context.Context, code string) (rfc6749.AuthorizationCode, error) {
//	authCode, err := m.store.FetchByCode(ctx, code)
//	if err != nil {
//		return nil, err
//	}
//
//	if authCode == nil {
//		return nil, ErrAuthorizationCodeNotFound
//	}
//
//	return authCode, nil
//}
//
//func (m *AuthorizationCodeManager) Save(ctx context.Context, authCode rfc6749.AuthorizationCode) error {
//	return m.store.Create(ctx, authCode)
//}
//
//func (m *AuthorizationCodeManager) DeleteByCode(ctx context.Context, code string) error {
//	return m.store.DeleteByCode(ctx, code)
//}
//
//func (m *AuthorizationCodeManager) Generate(gt grants.GrantType, client rfc6749.OAuthClient, userID string) rfc6749.AuthorizationCode {
//	switch gt {
//	case grants.GrantTypeAuthorizationCode:
//		var code string
//		if m.codeGenerator != nil {
//			code = m.codeGenerator(gt, client, userID)
//		} else {
//			code, _ = common.GenerateRandString(AuthorizationCodeLength, common.AlphaNum)
//		}
//
//		authCode := &models.AuthorizationCode{
//			Code: code,
//		}
//		// TODO - Continue to set more attributes
//		return authCode
//	default:
//		// TODO
//		return nil
//	}
//}
