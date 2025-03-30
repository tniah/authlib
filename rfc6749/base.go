package rfc6749

import (
	"encoding/json"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"net/http"
	"strings"
)

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
