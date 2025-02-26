package manage

import "errors"

var (
	ErrClientNotFound     = errors.New("client not found")
	ErrUnauthorizedClient = errors.New("unauthorized client")
)
