package authorizationcode

import (
	autherrors "github.com/tniah/authlib/errors"
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

func (f *Flow) validateAuthorizationRequest(r *requests.AuthorizationRequest) error {
	if err := f.validateNonce(r); err != nil {
		return err
	}

	return nil
}

func (f *Flow) validateNonce(r *requests.AuthorizationRequest) error {
	if err := r.ValidateNonce(true); err != nil {
		return err
	}

	if fn := f.existNonce; fn != nil {
		if fn(r.Nonce, r) {
			return autherrors.InvalidRequestError().
				WithDescription(ErrUsedNonce).
				WithState(r.State).
				WithRedirectURI(r.RedirectURI)
		}
	}

	return nil
}
