package requests

const (
	ScopeOpenID          = "openid"
	DisplayPage  Display = "page"
	DisplayPopup Display = "popup"
	DisplayTouch Display = "touch"
	DisplayWap   Display = "wap"

	ErrMissingClientID     = "missing \"client_id\" in request"
	ErrMissingRedirectURI  = "missing \"redirect_uri\" in request"
	ErrMissingNonce        = "missing \"nonce\" in request"
	ErrMissingResponseMode = "missing \"response_mode\" in request"
	ErrMissingResponseType = "missing \"response_type\" in request"
	ErrMissingDisplay      = "missing \"display\" in request"
	ErrInvalidDisplay      = "invalid \"display\" in request"

	ErrMissingGrantType         = "missing \"grant_type\" in request"
	ErrMissingAuthorizationCode = "missing \"code\" in request"
)
