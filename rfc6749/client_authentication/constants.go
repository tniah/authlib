package clientauth

import "errors"

var (
	ErrInvalidClient  = errors.New("invalid client")
	ErrNilClientStore = errors.New("client store is nil")
)
