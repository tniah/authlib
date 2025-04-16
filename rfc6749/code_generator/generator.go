package codegen

import (
	"errors"
	"github.com/tniah/authlib/common"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"time"
)

var (
	ErrNilClient = errors.New("client is nil")
	ErrNilUser   = errors.New("user is nil")
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

func (g *Generator) Generate(authCode models.AuthorizationCode, r *requests.AuthorizationRequest) error {
	client := r.Client
	if client == nil {
		return ErrNilClient
	}

	user := r.User
	if user == nil {
		return ErrNilUser
	}

	code, err := g.genCode(r.GrantType, client)
	if err != nil {
		return err
	}
	authCode.SetCode(code)

	authCode.SetClientID(client.GetClientID())
	authCode.SetUserID(user.GetSubjectID())
	authCode.SetRedirectURI(r.RedirectURI)
	authCode.SetResponseType(string(r.ResponseType))
	authCode.SetScopes(r.Scopes)
	authCode.SetState(r.State)
	authCode.SetAuthTime(time.Now())

	exp, err := g.expiresInHandler(r.GrantType, client)
	if err != nil {
		return err
	}
	authCode.SetExpiresIn(exp)

	if fn := g.extraDataGenerator; fn != nil {
		data, err := fn(r)
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
