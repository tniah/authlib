package ropc

import (
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	basegrant "github.com/tniah/authlib/rfc6749/base_grant"
	"net/http"
	"strings"
)

type Grant struct {
	clientAuthManager          ClientAuthManager
	userAuthManager            UserAuthManager
	tokenManager               TokenManager
	supportedClientAuthMethods map[string]bool
	*basegrant.TokenGrantMixin
}

func NewGrant(clientAuthMgr ClientAuthManager, userAuthMgr UserAuthManager, tokenMgr TokenManager) *Grant {
	return &Grant{
		clientAuthManager: clientAuthMgr,
		userAuthManager:   userAuthMgr,
		tokenManager:      tokenMgr,
		supportedClientAuthMethods: map[string]bool{
			AuthMethodClientSecretBasic: true,
		},
	}
}

func (grant *Grant) WithClientAuthMethods(methods map[string]bool) *Grant {
	grant.supportedClientAuthMethods = methods
	return grant
}

func (grant *Grant) CheckGrantType(grantType string) bool {
	return grantType == GrantTypeROPC
}

func (grant *Grant) checkParams(r *http.Request) error {
	if r.Method != http.MethodPost {
		return autherrors.InvalidRequestError().WithDescription(ErrRequestMustBePOST)
	}

	if !common.IsXWWWFormUrlencodedContentType(r) {
		return autherrors.InvalidRequestError().WithDescription(ErrNotContentTypeXWWWFormUrlencoded)
	}

	username := r.PostFormValue("username")
	if username == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingUsername)
	}

	password := r.PostFormValue("password")
	if password == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingPassword)
	}

	return nil
}

func (grant *Grant) authenticateClient(r *http.Request) (client models.Client, err error) {
	if client, err = grant.clientAuthManager.Authenticate(r, grant.supportedClientAuthMethods, EndpointToken); err != nil {
		return nil, err
	}

	if client == nil {
		return nil, autherrors.InvalidClientError()
	}

	if !client.CheckGrantType(GrantTypeROPC) {
		return nil, autherrors.UnauthorizedClientError().WithDescription(ErrClientUnsupportedROPC)
	}

	return client, nil
}

func (grant *Grant) authenticateUser(r *http.Request, client models.Client) (user models.User, err error) {
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	if user, err = grant.userAuthManager.Authenticate(username, password, client, r); err != nil {
		return nil, err
	}

	if user == nil {
		return nil, autherrors.InvalidRequestError().WithDescription(ErrIncorrectUsernameOrPassword)
	}

	return user, nil
}

func (grant *Grant) validateTokenRequest(r *http.Request) (client models.Client, user models.User, err error) {
	if err = grant.checkParams(r); err != nil {
		return nil, nil, err
	}

	if client, err = grant.authenticateClient(r); err != nil {
		return nil, nil, err
	}

	if user, err = grant.authenticateUser(r, client); err != nil {
		return nil, nil, err
	}

	return client, user, nil
}

func (grant *Grant) TokenResponse(r *http.Request, rw http.ResponseWriter) error {
	client, user, err := grant.validateTokenRequest(r)
	if err != nil {
		return err
	}

	requestedScopes := strings.Fields(r.FormValue("scope"))
	includeRefreshToken := client.CheckGrantType(GrantTypeRefreshToken)
	token, err := grant.tokenManager.GenerateAccessToken(r, GrantTypeROPC, client, user, requestedScopes, includeRefreshToken)
	if err != nil {
		return err
	}

	data := grant.StandardTokenData(token)
	// TODO implement a hook
	return grant.HandleTokenResponse(rw, data)
}
