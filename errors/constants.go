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
	ErrInvalidRequest           = errors.New("invalid_request")
	ErrUnauthorizedClient       = errors.New("unauthorized_client")
	ErrAccessDenied             = errors.New("access_denied")
	ErrUnsupportedResponseType  = errors.New("unsupported_response_type")
	ErrInvalidScope             = errors.New("invalid_scope")
	ErrInvalidClient            = errors.New("invalid_client")
	ErrInvalidGrant             = errors.New("invalid_grant")
	ErrUnsupportedGrantType     = errors.New("unsupported_grant_type")
	ErrUnsupportedTokenType     = errors.New("unsupported_token_type")
	ErrServerError              = errors.New("server_error")
	ErrTemporarilyUnavailable   = errors.New("temporarily_unavailable")
	ErrLoginRequired            = errors.New("login_required")
	ErrConsentRequired          = errors.New("consent_required")
	ErrAccountSelectionRequired = errors.New("account_selection_required")
)

// Descriptions error description
var Descriptions = map[error]string{
	ErrInvalidRequest:           "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
	ErrUnauthorizedClient:       "The client is not authorized to request an authorization code using this method",
	ErrAccessDenied:             "The resource owner or authorization server denied the request",
	ErrUnsupportedResponseType:  "The authorization server does not support obtaining an authorization code using this method",
	ErrInvalidScope:             "The requested scope is invalid, unknown, or malformed",
	ErrInvalidClient:            "Client authentication failed",
	ErrInvalidGrant:             "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client",
	ErrUnsupportedGrantType:     "The authorization grant type is not supported by the authorization server",
	ErrUnsupportedTokenType:     "The authorization token type is not supported by the authorization server",
	ErrServerError:              "The authorization server encountered an unexpected condition that prevented it from fulfilling the request",
	ErrTemporarilyUnavailable:   "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server",
	ErrLoginRequired:            "The authorization server requires end-user authentication. This error may be returned when the prompt parameter value in the authentication request is none, but the authentication request cannot be completed without displaying a user interface for end-user authentication",
	ErrConsentRequired:          "The authorization server requires end-user consent. This error may be returned when the prompt parameter value in the authentication Request is none, but the authentication request cannot be completed without displaying a user interface for end-User consent",
	ErrAccountSelectionRequired: "The end-user is required to select a session at the Authorization Server.",
}

// HttpCodes Http status code
var HttpCodes = map[error]int{
	ErrInvalidRequest:           http.StatusBadRequest,
	ErrUnauthorizedClient:       http.StatusUnauthorized,
	ErrAccessDenied:             http.StatusForbidden,
	ErrUnsupportedResponseType:  http.StatusUnauthorized,
	ErrInvalidScope:             http.StatusBadRequest,
	ErrInvalidClient:            http.StatusUnauthorized,
	ErrInvalidGrant:             http.StatusUnauthorized,
	ErrUnsupportedGrantType:     http.StatusUnauthorized,
	ErrUnsupportedTokenType:     http.StatusForbidden,
	ErrServerError:              http.StatusInternalServerError,
	ErrTemporarilyUnavailable:   http.StatusServiceUnavailable,
	ErrLoginRequired:            http.StatusUnauthorized,
	ErrConsentRequired:          http.StatusForbidden,
	ErrAccountSelectionRequired: http.StatusForbidden,
}
