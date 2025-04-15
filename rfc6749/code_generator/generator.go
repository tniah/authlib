package codegen

import (
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"net/http"
	"time"
)

type Generator struct {
	*Options
}

func New(opts ...*Options) *Generator {
	if len(opts) > 0 {
		return &Generator{opts[0]}
	}

	defaultOpts := NewOptions()
	return &Generator{defaultOpts}
}

func (g *Generator) Generate(grantType, responseType string, authCode models.AuthorizationCode, client models.Client, user models.User, scopes []string, redirectURI, state string, r *http.Request) error {
	code, err := g.genCode(grantType, client)
	if err != nil {
		return err
	}
	authCode.SetCode(code)

	authCode.SetClientID(client.GetClientID())
	authCode.SetUserID(user.GetSubjectID())
	authCode.SetRedirectURI(redirectURI)
	authCode.SetResponseType(responseType)
	authCode.SetScopes(scopes)
	authCode.SetState(state)
	authCode.SetAuthTime(time.Now())

	exp, err := g.expiresInHandler(grantType, client)
	if err != nil {
		return err
	}
	authCode.SetExpiresIn(exp)

	if fn := g.extraDataGenerator; fn != nil {
		data, err := fn(grantType, client, r)
		if err != nil {
			return err
		}
		authCode.SetExtraData(data)
	}

	return nil
}

func (g *Generator) genCode(grantType string, client models.Client) (string, error) {
	if fn := g.randStringGenerator; fn != nil {
		return fn(grantType, client)
	}

	return common.GenerateRandString(g.codeLength, common.AlphaNum)
}

func (g *Generator) expiresInHandler(grantType string, client models.Client) (time.Duration, error) {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.expiresIn, nil
}
