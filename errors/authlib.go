package errors

import (
	"errors"
	"net/http"
)

type AuthLibError struct {
	// State
	State string
	// RedirectURI
	RedirectURI string
	*OAuth2Error
}

type AuthLibErrorOption func(*AuthLibError)

func NewAuthLibError(code error, opts ...AuthLibErrorOption) *AuthLibError {
	e := &AuthLibError{
		OAuth2Error: NewOAuth2Error(code),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

func (e *AuthLibError) Data() map[string]interface{} {
	data := e.OAuth2Error.Data()
	if e.State != "" {
		data[ErrState] = e.State
	}
	return data
}

func (e *AuthLibError) Response() (statusCode int, header http.Header, data map[string]interface{}) {
	return e.HttpCode, e.HttpHeader, e.Data()
}

func WithDescription(desc string) AuthLibErrorOption {
	return func(e *AuthLibError) {
		e.Description = desc
	}
}

func WithErrorURI(uri string) AuthLibErrorOption {
	return func(e *AuthLibError) {
		e.URI = uri
	}
}

func WithState(state string) AuthLibErrorOption {
	return func(e *AuthLibError) {
		e.State = state
	}
}

func WithRedirectURI(redirectURI string) AuthLibErrorOption {
	return func(e *AuthLibError) {
		e.RedirectURI = redirectURI
	}
}

func ToAuthLibError(err error) (*AuthLibError, error) {
	var authErr *AuthLibError
	if errors.As(err, &authErr) {
		return authErr, nil
	}
	return nil, err
}

func NewInvalidRequestError(opts ...AuthLibErrorOption) *AuthLibError {
	return NewAuthLibError(ErrInvalidRequest, opts...)
}

func NewInvalidClientError(opts ...AuthLibErrorOption) *AuthLibError {
	return NewAuthLibError(ErrInvalidClient, opts...)
}

func NewUnauthorizedClientError(opts ...AuthLibErrorOption) *AuthLibError {
	return NewAuthLibError(ErrUnauthorizedClient, opts...)
}

func NewInvalidGrantError(opts ...AuthLibErrorOption) *AuthLibError {
	return NewAuthLibError(ErrInvalidGrant, opts...)
}

func NewUnsupportedResponseTypeError(opts ...AuthLibErrorOption) *AuthLibError {
	return NewAuthLibError(ErrUnsupportedResponseType, opts...)
}

func NewAccessDeniedError(opts ...AuthLibErrorOption) *AuthLibError {
	return NewAuthLibError(ErrAccessDenied, opts...)
}
