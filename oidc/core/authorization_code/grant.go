package authorizationcode

import (
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"net/http"
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

func (f *Flow) Authenticate(r *http.Request, client models.Client, redirectURI, state string) error {
	if err := f.validateAuthorizationRequest(r, redirectURI, state); err != nil {
		return err
	}
}

func (f *Flow) EnrichToken(token map[string]interface{}, client models.Client, user models.User) error {
	return nil
}

func (f *Flow) validateAuthorizationRequest(r *http.Request, redirectURI, state string) error {
	if err := f.validateNonce(r, redirectURI, state); err != nil {
		return err
	}

	return nil
}

func (f *Flow) validateNonce(r *http.Request, redirectURI, state string) error {
	nonce := r.FormValue(ParamNonce)
	if nonce == "" && f.requireNonce {
		return autherrors.InvalidRequestError().
			WithDescription(ErrMissingNonce).
			WithState(state).
			WithRedirectURI(redirectURI)
	}

	if fn := f.nonceValidator; fn != nil {
		if !fn(nonce, r) {
			return autherrors.InvalidRequestError().
				WithDescription(ErrUsedNonce).
				WithState(state).
				WithRedirectURI(redirectURI)
		}
	}

	return nil
}
