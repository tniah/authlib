package errors

import (
	"errors"
	"net/http"
)

const (
	errCode        = "error"
	errDescription = "error_description"
	errUri         = "error_uri"
	errState       = "state"
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
	ErrServerError:             http.StatusInternalServerError,
}
