package authorizationcode

import (
	"github.com/tniah/authlib/attributes"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
)

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
