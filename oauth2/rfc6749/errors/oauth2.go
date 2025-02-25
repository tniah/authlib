package errors

import (
	"errors"
	"fmt"
	"net/http"
)

type OAuth2Error struct {
	// Code a short-string error code
	Code error
	// Description human-readable text providing additional information,
	// used to assist the client developer in understanding the error that occurred
	Description string
	// Uri a URI identifying a human-readable web page with information about the error
	Uri string
	// State
	State string
	// RedirectUri
	RedirectUri string
	// StatusCode Http status code
	StatusCode int
	// Header Http header
	Header http.Header
}

type OAuth2ErrorOption func(*OAuth2Error)

func (e *OAuth2Error) Error() string {
	return fmt.Sprintf("error=%v | description=%s", e.Code, e.Description)
}

func New(code error, opts ...OAuth2ErrorOption) *OAuth2Error {
	statusCode := http.StatusBadRequest
	if v, ok := HttpCodes[code]; !ok {
		statusCode = v
	}

	e := &OAuth2Error{Code: code, StatusCode: statusCode}
	for _, opt := range opts {
		opt(e)
	}

	if e.Description == "" {
		if value, ok := Descriptions[code]; ok {
			e.Description = value
		}
	}

	e.Header = make(http.Header)
	return e
}

func WithDescription(desc string) OAuth2ErrorOption {
	return func(e *OAuth2Error) {
		e.Description = desc
	}
}

func WithErrUri(uri string) OAuth2ErrorOption {
	return func(e *OAuth2Error) {
		e.Uri = uri
	}
}

func WithState(state string) OAuth2ErrorOption {
	return func(e *OAuth2Error) {
		e.State = state
	}
}

func WithRedirectUri(redirectUri string) OAuth2ErrorOption {
	return func(e *OAuth2Error) {
		e.RedirectUri = redirectUri
	}
}

func WithStatusCode(status int) OAuth2ErrorOption {
	return func(e *OAuth2Error) {
		e.StatusCode = status
	}
}

func ToOAuth2Error(e error) (*OAuth2Error, error) {
	var err *OAuth2Error
	if ok := errors.As(e, &err); ok {
		return err, nil
	}
	return nil, err
}

func (e *OAuth2Error) Data() map[string]interface{} {
	data := map[string]interface{}{ErrCode: fmt.Sprint(e.Code)}

	if e.Description != "" {
		data[ErrDescription] = e.Description
	}

	if e.Uri != "" {
		data[ErrUri] = e.Uri
	}

	if e.State != "" {
		data[ErrState] = e.State
	}

	return data
}

func (e *OAuth2Error) Response() (statusCode int, header http.Header, data map[string]interface{}) {
	return e.StatusCode, e.Header, e.Data()
}

func NewInvalidRequestError(opts ...OAuth2ErrorOption) *OAuth2Error {
	return New(ErrInvalidRequest, opts...)
}

func NewUnauthorizedClientError(opts ...OAuth2ErrorOption) *OAuth2Error {
	return New(ErrUnauthorizedClient, opts...)
}

func NewUnsupportedResponseTypeError(opts ...OAuth2ErrorOption) *OAuth2Error {
	return New(ErrUnsupportedResponseType, opts...)
}

func NewAccessDeniedError(opts ...OAuth2ErrorOption) *OAuth2Error {
	return New(ErrAccessDenied, opts...)
}

func NewServerError(opts ...OAuth2ErrorOption) *OAuth2Error {
	return New(ErrServerError, opts...)
}
