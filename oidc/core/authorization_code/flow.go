package authorizationcode

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"github.com/tniah/authlib/utils"
	"time"
)

var (
	ErrNilAuthorizationCode = errors.New("authorization code is nil")
)

type Flow struct {
	*Config
}

func New(cfg *Config) *Flow {
	return &Flow{cfg}
}

func Must(cfg *Config) (*Flow, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return New(cfg), nil
}

func (f *Flow) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	if isOIDCReq := r.Scopes.ContainOpenID(); !isOIDCReq {
		return nil
	}

	if err := r.ValidateDisplay(false); err != nil {
		return err
	}

	if err := f.validateNonce(r); err != nil {
		return err
	}

	if err := f.validatePrompt(r); err != nil {
		return err
	}

	return nil
}

func (f *Flow) ValidateConsentRequest(r *requests.AuthorizationRequest) error {
	if err := f.ValidateAuthorizationRequest(r); err != nil {
		return err
	}

	user := r.User
	if len(r.Prompts) == 0 && utils.IsNil(user) {
		r.Prompts = types.Prompts{types.PromptLogin}
	}

	if utils.IsNil(user) && r.Prompts.ContainLogin() {
		return nil
	}

	if utils.IsNil(user) && r.Prompts.ContainNone() {
		return autherrors.LoginRequiredError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	if utils.IsNil(user) && r.Prompts.ContainConsent() {
		return autherrors.ConsentRequiredError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	if utils.IsNil(user) && r.Prompts.ContainSelectAccount() {
		return autherrors.AccountSelectionRequiredError().WithState(r.State).WithRedirectURI(r.RedirectURI)
	}

	return nil
}

func (f *Flow) ProcessAuthorizationCode(r *requests.AuthorizationRequest, authCode models.AuthorizationCode, params map[string]interface{}) error {
	authCode.SetNonce(r.Nonce)
	return nil
}

func (f *Flow) ProcessToken(r *requests.TokenRequest, token models.Token, data map[string]interface{}) error {
	if isOIDCReq := r.Scopes.ContainOpenID(); !isOIDCReq {
		return nil
	}

	if r.AuthCode == nil {
		return ErrNilAuthorizationCode
	}

	idToken, err := f.genIDToken(r)
	if err != nil {
		return err
	}

	data["id_token"] = idToken
	return nil
}

func (f *Flow) validateNonce(r *requests.AuthorizationRequest) error {
	if err := r.ValidateNonce(true); err != nil {
		return err
	}

	if fn := f.existNonce; fn != nil {
		if fn(r.Request.Context(), r.Nonce, r) {
			return autherrors.InvalidRequestError().
				WithDescription("\"nonce\" has been used").
				WithState(r.State).
				WithRedirectURI(r.RedirectURI)
		}
	}

	return nil
}

func (f *Flow) validatePrompt(r *requests.AuthorizationRequest) error {
	for _, prompt := range r.Prompts {
		if prompt.IsNone() && len(prompt) > 0 {
			return autherrors.InvalidRequestError().
				WithDescription("The prompt parameter \"none\" must only be used as a single value").
				WithState(r.State).
				WithRedirectURI(r.RedirectURI)
		}

		if prompt.IsLogin() {
			r.MaxAge = types.NewMaxAge(0)
		}
	}

	return nil
}

func (f *Flow) genIDToken(r *requests.TokenRequest) (string, error) {
	client := r.Client
	user := r.User
	authCode := r.AuthCode

	now := time.Now().UTC().Round(time.Second)
	claims := utils.JWTClaim{
		"iss": f.issuerHandler(r.Request.Context(), client),
		"aud": []string{client.GetClientID()},
		"exp": jwt.NewNumericDate(now.Add(f.expiresInHandler(r.Request.Context(), r.GrantType.String(), client))),
		"iat": jwt.NewNumericDate(now),
	}

	authTime := authCode.GetAuthTime()
	if authTime.IsZero() {
		authTime = now
	}
	claims["auth_time"] = jwt.NewNumericDate(authTime)

	if nonce := authCode.GetNonce(); nonce != "" {
		claims["nonce"] = nonce
	}

	if userID := user.GetUserID(); userID != "" {
		claims["sub"] = userID
	}

	if fn := f.extraClaimGenerator; fn != nil {
		extraClaims, err := fn(r.Request.Context(), r.GrantType.String(), client, user)
		if err != nil {
			return "", err
		}

		for k, v := range extraClaims {
			claims[k] = v
		}
	}

	key, method, keyID, err := f.signingKeyHandler(r.Request.Context(), client)
	if err != nil {
		return "", err
	}

	t, err := utils.NewJWTToken(key, method, keyID)
	if err != nil {
		return "", err
	}

	idToken, err := t.Generate(claims, utils.JWTHeader{})
	if err != nil {
		return "", err
	}

	return idToken, nil
}

func (f *Flow) issuerHandler(ctx context.Context, client models.Client) string {
	if fn := f.issuerGenerator; fn != nil {
		return fn(ctx, client)
	}

	return f.issuer
}

func (f *Flow) expiresInHandler(ctx context.Context, grantType string, client models.Client) time.Duration {
	if fn := f.expiresInGenerator; fn != nil {
		return fn(ctx, grantType, client)
	}

	return f.expiresIn
}

func (f *Flow) signingKeyHandler(ctx context.Context, client models.Client) ([]byte, jwt.SigningMethod, string, error) {
	if fn := f.signingKeyGenerator; fn != nil {
		return fn(ctx, client)
	}

	return f.signingKey, f.signingKeyMethod, f.signingKeyID, nil
}
