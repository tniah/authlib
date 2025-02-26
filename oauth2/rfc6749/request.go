package rfc6749

type authorizationRequest struct {
	responseType string
	clientID     string
	redirectURI  string
	scopes       []string
	state        string
	userID       string
	client
}
