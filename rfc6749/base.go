package rfc6749

import (
	"encoding/json"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/utils"
	"net/http"
	"strings"
)

type TokenFlowMixin struct{}

func (f *TokenFlowMixin) StandardTokenData(token models.Token) map[string]interface{} {
	data := map[string]interface{}{
		"token_type":   token.GetType(),
		"access_token": token.GetAccessToken(),
		"expires_in":   token.GetAccessTokenExpiresIn().Seconds(),
	}

	if refreshToken := token.GetRefreshToken(); refreshToken != "" {
		data["refresh_token"] = refreshToken
	}

	if scopes := token.GetScopes(); len(scopes) > 0 {
		data["scope"] = strings.Join(scopes, " ")
	}

	return data
}

func (f *TokenFlowMixin) HandleTokenResponse(rw http.ResponseWriter, data map[string]interface{}) error {
	for k, v := range utils.JSONHeaders() {
		rw.Header().Set(k, v)
	}

	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(data)
}
