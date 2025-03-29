package rfc6749

import (
	"encoding/json"
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"net/http"
	"strings"
)

type AuthorizationGrantMixin struct{}

func (grant *AuthorizationGrantMixin) ValidateRedirectURI(r *requests.AuthorizationRequest, client models.Client) (string, error) {
	redirectURI := r.RedirectURI
	if redirectURI == "" {
		redirectURI = client.GetDefaultRedirectURI()

		if redirectURI == "" {
			return "", autherrors.InvalidRequestError().WithDescription(ErrMissingRedirectURI).WithState(r.State)
		}

		return redirectURI, nil
	}

	if allowed := client.CheckRedirectURI(redirectURI); !allowed {
		return "", autherrors.InvalidRequestError().WithDescription(ErrUnsupportedRedirectURI).WithState(r.State)
	}

	return redirectURI, nil
}

type TokenGrantMixin struct{}

func (grant *TokenGrantMixin) StandardTokenData(token models.Token) map[string]interface{} {
	data := map[string]interface{}{
		ParamTokeType:    token.GetType(),
		ParamAccessToken: token.GetAccessToken(),
		ParamExpiresIn:   token.GetAccessTokenExpiresIn().Seconds(),
	}

	if refreshToken := token.GetRefreshToken(); refreshToken != "" {
		data[ParamRefreshToken] = refreshToken
	}

	if scopes := token.GetScopes(); len(scopes) > 0 {
		data[ParamScope] = strings.Join(scopes, " ")
	}

	return data
}

func (grant *TokenGrantMixin) HandleTokenResponse(rw http.ResponseWriter, data map[string]interface{}) error {
	for k, v := range common.DefaultJSONHeader() {
		rw.Header().Set(k, v)
	}

	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(data)
}
