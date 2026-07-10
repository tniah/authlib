package errors

import "errors"

// JWT signing config errors shared by rfc9068 (JWT access tokens) and
// oidc/core/authorization_code (ID tokens).
var (
	ErrMissingIssuer           = errors.New("\"issuer\" or \"issuerGenerator\" is required")
	ErrMissingExpiresIn        = errors.New("\"expiresIn\" or \"expiresInGenerator\" is required")
	ErrMissingSigningKey       = errors.New("\"signingKey\" or \"signingKeyGenerator\" is required")
	ErrMissingSigningKeyMethod = errors.New("\"signingKeyMethod\" is required")
)
