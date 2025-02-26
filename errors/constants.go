package errors

import (
	"errors"
	"net/http"
)

const (
	ErrCode        = "error"
	ErrDescription = "error_description"
	ErrUri         = "error_uri"
	ErrState       = "state"
)

var (
	ErrInvalidRequest          = errors.New("invalid_request")
	ErrUnauthorizedClient      = errors.New("unauthorized_client")
	ErrAccessDenied            = errors.New("access_denied")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrInvalidScope            = errors.New("invalid_scope")
	ErrInvalidClient           = errors.New("invalid_client")
	ErrInvalidGrant            = errors.New("invalid_grant")
	ErrServerError             = errors.New("server_error")
	ErrTemporarilyUnavailable  = errors.New("temporarily_unavailable")
)

// Descriptions error description
var Descriptions = map[error]string{
	ErrInvalidRequest:          "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
	ErrUnauthorizedClient:      "The client is not authorized to request an authorization code using this method",
	ErrAccessDenied:            "The resource owner or authorization server denied the request",
	ErrUnsupportedResponseType: "The authorization server does not support obtaining an authorization code using this method",
	ErrInvalidScope:            "The requested scope is invalid, unknown, or malformed",
	ErrInvalidClient:           "Client authentication failed",
	ErrInvalidGrant:            "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client",
	ErrServerError:             "The authorization server encountered an unexpected condition that prevented it from fulfilling the request",
	ErrTemporarilyUnavailable:  "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server",
}

// HttpCodes Http status code
var HttpCodes = map[error]int{
	ErrInvalidRequest:          http.StatusBadRequest,
	ErrUnauthorizedClient:      http.StatusUnauthorized,
	ErrAccessDenied:            http.StatusForbidden,
	ErrUnsupportedResponseType: http.StatusUnauthorized,
	ErrInvalidScope:            http.StatusBadRequest,
	ErrInvalidClient:           http.StatusUnauthorized,
	ErrInvalidGrant:            http.StatusUnauthorized,
	ErrServerError:             http.StatusInternalServerError,
	ErrTemporarilyUnavailable:  http.StatusServiceUnavailable,
}
