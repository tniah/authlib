package rfc6749

import (
	"encoding/json"
	"github.com/tniah/authlib/common"
	autherrors "github.com/tniah/authlib/errors"
	"github.com/tniah/authlib/models"
	"net/http"
	"strings"
)

const (
	ParamTokenType    = "token_type"
	ParamAccessToken  = "access_token"
	ParamExpiresIn    = "expires_in"
	ParamRefreshToken = "refresh_token"
	ParamScope        = "scope"

	ErrRequestMustBePOST                = "request must be POST"
	ErrNotContentTypeXWWWFormUrlencoded = "content type must be \"application/x-www-form-urlencoded\""
)

type TokenFlowMixin struct{}

func (f *TokenFlowMixin) CheckTokenRequest(r *http.Request) error {
	if r.Method != http.MethodPost {
		return autherrors.InvalidRequestError().WithDescription(ErrRequestMustBePOST)
	}

	if !common.IsXWWWFormUrlencodedContentType(r) {
		return autherrors.InvalidRequestError().WithDescription(ErrNotContentTypeXWWWFormUrlencoded)
	}

	return nil
}

func (f *TokenFlowMixin) StandardTokenData(token models.Token) map[string]interface{} {
	data := map[string]interface{}{
		ParamTokenType:   token.GetType(),
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

func (f *TokenFlowMixin) HandleTokenResponse(rw http.ResponseWriter, data map[string]interface{}) error {
	for k, v := range common.DefaultJSONHeader() {
		rw.Header().Set(k, v)
	}

	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(data)
}
