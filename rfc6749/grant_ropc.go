package rfc6749

import (
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"net/http"
	"strings"
)

type ROPCGrant struct {
	mgr *ROPCGrantManager
	*TokenGrantMixin
}

func NewROPCGrant(mgr *ROPCGrantManager) *ROPCGrant {
	return &ROPCGrant{mgr: mgr}
}

func MustROPCGrant(mgr *ROPCGrantManager) *ROPCGrant {
	if err := mgr.Validate(); err != nil {
		panic(err)
	}

	return NewROPCGrant(mgr)
}

func (grant *ROPCGrant) CheckGrantType(gt string) bool {
	return gt == GrantTypeROPC
}

func (grant *ROPCGrant) CheckParams(r *http.Request) error {
	if r.Method != http.MethodPost {
		return autherrors.InvalidRequestError().WithDescription(ErrRequestMustBePost)
	}

	if !common.IsXWwwFormUrlencodedContentType(r) {
		return autherrors.InvalidRequestError().WithDescription(ErrNotXWwwFormUrlencoded)
	}

	username := r.PostFormValue(ParamUsername)
	if username == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingUsername)
	}

	password := r.PostFormValue(ParamPassword)
	if password == "" {
		return autherrors.InvalidRequestError().WithDescription(ErrMissingPassword)
	}

	return nil
}

func (grant *ROPCGrant) AuthenticateClient(r *http.Request) (client models.Client, err error) {
	if client, err = grant.mgr.clientAuthHandler(r, grant.mgr.clientAuthMethods, EndpointNameToken); err != nil {
		return nil, err
	}

	if client == nil {
		return nil, autherrors.InvalidClientError()
	}

	if !client.CheckGrantType(GrantTypeROPC) {
		return nil, autherrors.UnauthorizedClientError().WithDescription(ErrUnsupportedROPCGrant)
	}

	return client, nil
}

func (grant *ROPCGrant) AuthenticateUser(r *http.Request) (user models.User, err error) {
	username := r.PostFormValue(ParamUsername)
	password := r.PostFormValue(ParamPassword)

	if user, err = grant.mgr.userAuthHandler(username, password); err != nil {
		return nil, err
	}

	if user == nil {
		return nil, autherrors.InvalidRequestError().WithDescription(ErrUsernameOrPasswordIncorrect)
	}

	return user, nil
}

func (grant *ROPCGrant) AuthenticateRequest(r *http.Request) (client models.Client, user models.User, err error) {
	if err = grant.CheckParams(r); err != nil {
		return nil, nil, err
	}

	if client, err = grant.AuthenticateClient(r); err != nil {
		return nil, nil, err
	}

	if user, err = grant.AuthenticateUser(r); err != nil {
		return nil, nil, err
	}

	return client, user, nil
}

func (grant *ROPCGrant) TokenResponse(r *http.Request, rw http.ResponseWriter) error {
	client, user, err := grant.AuthenticateRequest(r)
	if err != nil {
		return err
	}

	requestedScopes := strings.Fields(r.FormValue(ParamScope))
	includeRefreshToken := client.CheckGrantType(GrantTypeRefreshToken)
	token, err := grant.mgr.accessTokenGenerator(r, GrantTypeROPC, client, user, requestedScopes, includeRefreshToken)
	if err != nil {
		return err
	}

	data := grant.StandardTokenData(token)
	// TODO implement a hook
	return grant.HandleTokenResponse(rw, data)
}
