package clientauth

import "errors"

var (
	ErrInvalidClient  = errors.New("invalid client")
	ErrNilClientStore = errors.New("client store is nil")
)

const (
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodNone              = "none"
)
