package authorizationcode

const (
	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"

	ParamNonce = "nonce"

	ErrMissingNonce = "Missing \"nonce\" in request"
	ErrUsedNonce    = "\"nonce\" has been used"
)
