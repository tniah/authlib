package authorizationcode

import (
	"errors"
	"github.com/tniah/authlib/attributes"
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"time"
)

var ErrNilAuthorizationCode = errors.New("authorization code is nil")

type Flow struct {
	*Config
}

func New(cfg *Config) *Flow {
	return &Flow{cfg}
}

func Must(cfg *Config) (*Flow, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return New(cfg), nil
}

func (f *Flow) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	if !r.ContainOpenIDScope() {
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
	if (r.Prompts == nil || len(r.Prompts) == 0) && user == nil {
		r.Prompts = attributes.SpaceDelimitedArray{attributes.PromptLogin}
	}

	return nil
}

func (f *Flow) ProcessAuthorizationCode(r *requests.AuthorizationRequest, authCode models.AuthorizationCode, params *map[string]interface{}) error {
	authCode.SetNonce(r.Nonce)
	return nil
}

func (f *Flow) ProcessToken(r *requests.TokenRequest, token models.Token, data map[string]interface{}) error {
	if !f.containOpenIDScope(token.GetScopes()) {
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
		if fn(r.Nonce, r) {
			return autherrors.InvalidRequestError().
				WithDescription("\"nonce\" has been used").
				WithState(r.State).
				WithRedirectURI(r.RedirectURI)
		}
	}

	return nil
}

func (f *Flow) validatePrompt(r *requests.AuthorizationRequest) error {
	if err := r.ValidatePrompts(false); err != nil {
		return err
	}

	for _, prompt := range r.Prompts {
		if prompt == attributes.PromptNone && len(prompt) > 0 {
			return autherrors.InvalidRequestError().
				WithDescription("The prompt parameter \"none\" must only be used as a single value").
				WithState(r.State).
				WithRedirectURI(r.RedirectURI)
		}

		if prompt == attributes.PromptLogin {
			r.MaxAge = attributes.NewMaxAge(0)
		}
	}

	return nil
}

func (f *Flow) containOpenIDScope(scopes []string) bool {
	if len(scopes) == 0 {
		return false
	}

	for _, scope := range scopes {
		if scope == attributes.ScopeOpenID {
			return true
		}
	}

	return false
}

func (f *Flow) genIDToken(r *requests.TokenRequest) (string, error) {
	client := r.Client
	user := r.User
	authCode := r.AuthCode

	now := time.Now()
	claims := common.JWTClaim{
		"iss": f.Issuer(client),
		"aud": []string{client.GetClientID()},
		"exp": now.Add(f.ExpiresIn(r.GrantType, client)),
		"iat": now,
	}

	authTime := authCode.GetAuthTime()
	if authTime.IsZero() {
		authTime = now
	}
	claims["auth_time"] = authTime

	if nonce := authCode.GetNonce(); nonce != "" {
		claims["nonce"] = nonce
	}

	if userID := user.GetSubjectID(); userID != "" {
		claims["sub"] = userID
	}

	key, method, keyID := f.SigningKey(client)
	t, err := common.NewJWTToken(key, method, keyID)
	if err != nil {
		return "", err
	}

	idToken, err := t.Generate(claims, common.JWTHeader{})
	if err != nil {
		return "", err
	}

	return idToken, nil
}
