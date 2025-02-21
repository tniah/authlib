package grants

const (
	ErrDescMissingClientId     = "Missing \"client_id\" parameter in request"
	ErrDescClientIDNotFound    = "No client was found that matches \"client_id\" value"
	ErrDescMissingResponseType = "Missing \"response_type\" parameter in request"
	ErrDescMissingRedirectUri  = "Missing \"redirect_uri\" parameter in request"
	ErrDescInvalidRedirectUri  = "Redirect URI is not supported by client"
)
