package authorizationcode

import (
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/rfc6749"
	"net/http"
)

type Grant struct {
	clientManager              ClientManager
	userManager                UserManager
	authCodeManager            AuthCodeManager
	tokenManager               TokenManager
	supportedClientAuthMethods map[string]bool
	*rfc6749.TokenGrantMixin
}

func New(clientMgr ClientManager, userMgr UserManager, authCodeMgr AuthCodeManager, tokenMgr TokenManager) (*Grant, error) {
	if clientMgr == nil {
		return nil, ErrNilClientManager
	}

	if userMgr == nil {
		return nil, ErrNilUserManager
	}

	if authCodeMgr == nil {
		return nil, ErrNilAuthCodeManager
	}

	if tokenMgr == nil {
		return nil, ErrNilTokenManager
	}

	return &Grant{
		supportedClientAuthMethods: map[string]bool{
			AuthMethodClientSecretBasic: true,
			AuthMethodNone:              true,
		},
		TokenGrantMixin: &rfc6749.TokenGrantMixin{
			GrantType: GrantTypeAuthorizationCode,
		},
	}, nil
}

func (g *Grant) CheckGrantType(grantType string) bool {
	return grantType == GrantTypeAuthorizationCode
}

func (g *Grant) CheckResponseType(rt string) bool {
	return rt == ResponseTypeCode
}

func (g *Grant) AuthorizationResponse(r *http.Request, rw http.ResponseWriter) error {
	state := r.URL.Query().Get(ParamState)
	client, err := g.checkClient(r, state)
	if err != nil {
		return err
	}

	redirectURI, err := g.ValidateRedirectURI(r, client, state)
	if err != nil {
		return err
	}

	if err = g.validateResponseType(r, client, redirectURI, state); err != nil {
		return err
	}

	user, err := g.authenticateUser(r, client, redirectURI, state)
	if err != nil {
		return err
	}

	authCode, err := g.generateAuthCode(r, client, user)
	if err != nil {
		return err
	}

	params := map[string]interface{}{
		ParamCode: authCode.GetCode(),
	}
	if state != "" {
		params[state] = state
	}

	return common.Redirect(rw, redirectURI, params)
}

func (g *Grant) checkClient(r *http.Request, state string) (client models.Client, err error) {
	clientID := r.URL.Query().Get(ParamClientID)
	if clientID == "" {
		return nil, autherrors.InvalidRequestError().WithDescription(ErrMissingClientID).WithState(state)
	}

	if client, err = g.clientManager.FetchByClientID(r.Context(), clientID); err != nil {
		return nil, err
	}

	if client == nil {
		return nil, autherrors.InvalidRequestError().WithDescription(ErrClientNotFound).WithState(state)
	}

	return client, nil
}

func (g *Grant) ValidateRedirectURI(r *http.Request, client models.Client, state string) (string, error) {
	redirectURI := r.URL.Query().Get(ParamRedirectURI)
	if redirectURI == "" {
		redirectURI = client.GetDefaultRedirectURI()

		if redirectURI == "" {
			return "", autherrors.InvalidRequestError().WithDescription(ErrMissingRedirectURI).WithState(state)
		}

		return redirectURI, nil
	}

	if allowed := client.CheckRedirectURI(redirectURI); !allowed {
		return "", autherrors.InvalidRequestError().WithDescription(ErrUnsupportedRedirectURI).WithState(state)
	}

	return redirectURI, nil
}

func (g *Grant) validateResponseType(r *http.Request, client models.Client, redirectURI, state string) error {
	responseType := r.URL.Query().Get(ParamResponseType)

	if responseType == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingResponseType).WithRedirectURI(redirectURI).WithState(state)
	}

	if !g.CheckResponseType(responseType) {
		return autherrors.UnsupportedResponseTypeError().WithRedirectURI(redirectURI).WithState(state)
	}

	if allowed := client.CheckResponseType(responseType); !allowed {
		return autherrors.UnauthorizedClientError().WithRedirectURI(redirectURI).WithState(state)
	}

	return nil
}

func (g *Grant) authenticateUser(r *http.Request, client models.Client, redirectURI, state string) (models.User, error) {
	user, err := g.userManager.Authenticate(r, client)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, autherrors.AccessDeniedError().WithState(state).WithRedirectURI(redirectURI)
	}

	return user, nil
}

func (g *Grant) generateAuthCode(r *http.Request, client models.Client, user models.User) (models.AuthorizationCode, error) {
	authCode, err := g.authCodeManager.Generate(GrantTypeAuthorizationCode, client, user, r)
	if err != nil {
		return nil, err
	}

	if authCode == nil {
		return nil, ErrNilAuthCode
	}

	return authCode, nil
}

func (g *Grant) checkTokenRequestParams(r *http.Request) error {
	if r.Method != http.MethodPost {
		return autherrors.InvalidRequestError().WithDescription(ErrRequestMustBePOST)
	}

	if !common.IsXWWWFormUrlencodedContentType(r) {
		return autherrors.InvalidRequestError().WithDescription(ErrNotContentTypeXWWWFormUrlencoded)
	}

}

func (g *Grant) authenticateClient(r *http.Request) (models.Client, error) {
	client, err := g.clientManager.Authenticate(r, g.supportedClientAuthMethods, EndpointToken)
	if err != nil {
		return nil, err
	}

	if client == nil {
		return nil, autherrors.InvalidClientError()
	}

	return client, nil
}

func (g *Grant) validateAuthCode(r *http.Request, client models.Client) (models.AuthorizationCode, error) {

}
