package errors

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrInvalidRequest          = errors.New("invalid_request")
	ErrUnauthorizedClient      = errors.New("unauthorized_client")
	ErrAccessDenied            = errors.New("access_denied")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrInvalidScope            = errors.New("invalid_scope")
	ErrServerError             = errors.New("server_error")
	ErrTemporarilyUnavailable  = errors.New("temporarily_unavailable")
)

// Descriptions error description
var Descriptions = map[error]string{
	ErrInvalidRequest:          "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
	ErrUnauthorizedClient:      "The client is not authorized to request an authorization code using this method",
	ErrAccessDenied:            "The resource owner or authorization server denied the request",
	ErrUnsupportedResponseType: "The authorization server does not support obtaining an authorization code using this method",
	ErrServerError:             "The authorization server encountered an unexpected condition that prevented it from fulfilling the request",
}

// HttpCodes Http status code
var HttpCodes = map[error]int{
	ErrInvalidRequest:          http.StatusBadRequest,
	ErrUnauthorizedClient:      http.StatusUnauthorized,
	ErrAccessDenied:            http.StatusForbidden,
	ErrUnsupportedResponseType: http.StatusUnauthorized,
}

type OAuth2Error struct {
	// Code an error code
	Code error
	// Description human-readable text providing additional information,
	// used to assist the client developer in understanding the error that occurred
	Description string
	// ErrorUri a URI identifying a human-readable web page with information about the error
	ErrorUri string
	// State if a "state" parameter was present in the authorization request. The exact value received from the client
	State string
	// RedirectUri
	RedirectUri string

	// HttpCode HTTP code
	HttpCode int
	// HttpHeader HTTP headers
	HttpHeader http.Header
}

func (e *OAuth2Error) Error() string {
	return fmt.Sprintf("error=%v | description=%s", e.Code, e.Description)
}

type ErrorOption func(*OAuth2Error)

func WithDescription(description string) ErrorOption {
	return func(e *OAuth2Error) {
		e.Description = description
	}
}

func WithErrUri(uri string) ErrorOption {
	return func(e *OAuth2Error) {
		e.ErrorUri = uri
	}
}

func WithState(state string) ErrorOption {
	return func(e *OAuth2Error) {
		e.State = state
	}
}

func WithRedirectUri(uri string) ErrorOption {
	return func(e *OAuth2Error) {
		e.RedirectUri = uri
	}
}

func NewOAuth2Error(e error, opts ...ErrorOption) *OAuth2Error {
	err := &OAuth2Error{Code: e, HttpCode: http.StatusBadRequest}
	for _, opt := range opts {
		opt(err)
	}

	if code, ok := HttpCodes[err.Code]; ok {
		err.HttpCode = code
	}

	if err.Description == "" {
		if value, ok := Descriptions[e]; ok {
			err.Description = value
		}
	}

	return err
}

func NewInvalidRequestError(opts ...ErrorOption) *OAuth2Error {
	return NewOAuth2Error(ErrInvalidRequest, opts...)
}

func NewUnauthorizedClientError(opts ...ErrorOption) *OAuth2Error {
	return NewOAuth2Error(ErrUnauthorizedClient, opts...)
}

func NewUnsupportedResponseTypeError(opts ...ErrorOption) *OAuth2Error {
	return NewOAuth2Error(ErrUnsupportedResponseType, opts...)
}

func NewAccessDeniedError(opts ...ErrorOption) *OAuth2Error {
	return NewOAuth2Error(ErrAccessDenied, opts...)
}

func NewServerError(opts ...ErrorOption) *OAuth2Error {
	return NewOAuth2Error(ErrServerError, opts...)
}
