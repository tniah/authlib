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

func NewAuthLibError(code error) *AuthLibError {
	return &AuthLibError{
		OAuth2Error: NewOAuth2Error(code),
	}
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

func (e *AuthLibError) WithDescription(desc string) *AuthLibError {
	e.Description = desc
	return e
}

func (e *AuthLibError) WithErrorURI(uri string) *AuthLibError {
	e.URI = uri
	return e
}

func (e *AuthLibError) WithState(state string) *AuthLibError {
	e.State = state
	return e
}

func (e *AuthLibError) WithRedirectURI(redirectURI string) *AuthLibError {
	e.RedirectURI = redirectURI
	return e
}

func ToAuthLibError(err error) (*AuthLibError, error) {
	var authErr *AuthLibError

	if errors.As(err, &authErr) {
		return authErr, nil
	}

	return nil, err
}

func InvalidRequestError() *AuthLibError {
	return NewAuthLibError(ErrInvalidRequest)
}

func InvalidClientError() *AuthLibError {
	return NewAuthLibError(ErrInvalidClient)
}

func UnauthorizedClientError() *AuthLibError {
	return NewAuthLibError(ErrUnauthorizedClient)
}

func InvalidGrantError() *AuthLibError {
	return NewAuthLibError(ErrInvalidGrant)
}

func UnsupportedGrantTypeError() *AuthLibError {
	return NewAuthLibError(ErrUnsupportedGrantType)
}

func UnsupportedResponseTypeError() *AuthLibError {
	return NewAuthLibError(ErrUnsupportedResponseType)
}

func AccessDeniedError() *AuthLibError {
	return NewAuthLibError(ErrAccessDenied)
}

func UnsupportedTokenType() *AuthLibError {
	return NewAuthLibError(ErrUnsupportedTokenType)
}

func InternalServerError() *AuthLibError {
	return NewAuthLibError(ErrServerError)
}

func LoginRequiredError() *AuthLibError {
	return NewAuthLibError(ErrLoginRequired)
}

func ConsentRequiredError() *AuthLibError {
	return NewAuthLibError(ErrConsentRequired)
}

func AccountSelectionRequiredError() *AuthLibError {
	return NewAuthLibError(ErrAccountSelectionRequired)
}
