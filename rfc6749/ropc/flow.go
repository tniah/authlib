package ropc

import (
	"errors"
	"fmt"
	"net/http"

	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/rfc6749"
	"github.com/tniah/authlib/types"
	"github.com/tniah/authlib/utils"
)

const EndpointToken = "token"

var ErrNilToken = errors.New("token is nil")

// Flow implements the Resource Owner Password Credentials grant (RFC 6749 §4.3).
// It authenticates both the client and the end-user on a single /token request.
// NOTE: ROPC is a legacy grant; prefer Authorization Code + PKCE for new integrations.
type Flow struct {
	*Config
	*rfc6749.TokenFlowMixin
}

// New creates a Flow without validating config. Use Must for production use.
func New(cfg *Config) *Flow {
	return &Flow{Config: cfg}
}

// Must creates a Flow and returns an error if the config is incomplete.
func Must(cfg *Config) (*Flow, error) {
	if err := cfg.ValidateConfig(); err != nil {
		return nil, err
	}

	return New(cfg), nil
}

// CheckGrantType reports whether this flow handles the given grant_type.
func (f *Flow) CheckGrantType(gt types.GrantType) bool {
	return gt.IsROPC()
}

func (f *Flow) ValidateTokenRequest(r *requests.TokenRequest) error {
	if err := f.checkParams(r); err != nil {
		return err
	}

	if err := f.authenticateClient(r); err != nil {
		return err
	}

	if err := f.authenticateUser(r); err != nil {
		return err
	}

	for _, h := range f.tokenReqValidators {
		if err := h.ValidateTokenRequest(r); err != nil {
			return err
		}
	}

	return nil
}

func (f *Flow) TokenResponse(r *requests.TokenRequest, rw http.ResponseWriter) error {
	token, err := f.genToken(r)
	if err != nil {
		return err
	}

	data := f.StandardTokenData(token)
	for _, h := range f.tokenProcessors {
		if err = h.ProcessToken(r, token, data); err != nil {
			return err
		}
	}

	if err = f.tokenMgr.Save(r.Request.Context(), token); err != nil {
		return err
	}

	return f.HandleTokenResponse(rw, data)
}

func (f *Flow) checkParams(r *requests.TokenRequest) error {
	if err := f.checkTokenEndpointHttpMethod(r); err != nil {
		return err
	}

	if err := f.validateGrantType(r); err != nil {
		return err
	}

	if err := r.ValidateUsername(); err != nil {
		return err
	}

	if err := r.ValidatePassword(); err != nil {
		return err
	}

	return nil
}

func (f *Flow) checkTokenEndpointHttpMethod(r *requests.TokenRequest) error {
	for _, method := range f.tokenEndpointHttpMethods {
		if r.Method() == method {
			return nil
		}
	}

	return autherrors.InvalidRequestError().WithDescription(fmt.Sprintf("unsupported http method \"%s\"", r.Method()))
}

func (f *Flow) validateGrantType(r *requests.TokenRequest) error {
	if err := r.ValidateGrantType(); err != nil {
		return err
	}

	if valid := r.GrantType.IsROPC(); !valid {
		return autherrors.UnsupportedGrantTypeError()
	}

	return nil
}

func (f *Flow) authenticateClient(r *requests.TokenRequest) error {
	client, err := f.clientMgr.Authenticate(r.Request, f.supportedClientAuthMethods, EndpointToken)
	if err != nil || utils.IsNil(client) {
		return autherrors.InvalidClientError().WithCause(err)
	}

	// Verify the client is explicitly permitted to use the password grant.
	if allowed := client.CheckGrantType(types.GrantTypeROPC); !allowed {
		return autherrors.UnauthorizedClientError().WithDescription("The client is not authorized to use grant type \"password\"")
	}

	r.Client = client
	return nil
}

func (f *Flow) authenticateUser(r *requests.TokenRequest) error {
	user, err := f.userMgr.Authenticate(r.Username, r.Password, r.Client, r.Request)
	if err != nil || utils.IsNil(user) {
		// Return a generic message to avoid leaking whether the username exists.
		return autherrors.InvalidGrantError().WithDescription("Username or password is incorrect").WithCause(err)
	}

	r.User = user
	return nil
}

func (f *Flow) genToken(r *requests.TokenRequest) (models.Token, error) {
	token := f.tokenMgr.New()
	if utils.IsNil(token) {
		return nil, ErrNilToken
	}

	// Include a refresh token only if the client has the refresh_token grant enabled.
	if err := f.tokenMgr.Generate(token, r, r.Client.CheckGrantType(types.GrantTypeRefreshToken)); err != nil {
		return nil, err
	}

	return token, nil
}
