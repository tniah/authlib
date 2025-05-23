package codegen

import (
	"errors"
	"github.com/tniah/authlib/models"
	"github.com/tniah/authlib/requests"
	"github.com/tniah/authlib/types"
	"github.com/tniah/authlib/utils"
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

	code := g.genCode(r.GrantType, client)
	authCode.SetCode(code)
	authCode.SetClientID(client.GetClientID())
	authCode.SetUserID(user.GetUserID())
	authCode.SetRedirectURI(r.RedirectURI)
	authCode.SetResponseType(r.ResponseType)
	authCode.SetScopes(r.Scopes)
	authCode.SetState(r.State)
	authCode.SetAuthTime(time.Now().UTC().Round(time.Second))
	exp := g.expiresInHandler(r.GrantType, client)
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

func (g *Generator) genCode(grantType types.GrantType, client models.Client) string {
	if fn := g.randStringGenerator; fn != nil {
		return fn(grantType, client)
	}

	s, _ := utils.GenerateRandString(g.codeLength, utils.AlphaNum)
	return s
}

func (g *Generator) expiresInHandler(grantType types.GrantType, client models.Client) time.Duration {
	if fn := g.expiresInGenerator; fn != nil {
		return fn(grantType, client)
	}

	return g.expiresIn
}
