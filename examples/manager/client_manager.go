package manager

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/tniah/authlib/integrations/sql"
	authlibmodels "github.com/tniah/authlib/models"
	clientauth "github.com/tniah/authlib/rfc6749/client_authentication"
	authlibtypes "github.com/tniah/authlib/types"
)

type ClientManager struct {
	lock    sync.Mutex
	mgr     *clientauth.Manager
	clients map[string]*sql.Client
}

func NewClientManager() *ClientManager {
	m := &ClientManager{
		mgr: clientauth.NewManager(),
		clients: map[string]*sql.Client{
			"public_client": {
				ClientName:              "Public client",
				ClientID:                "public_client",
				RedirectURIs:            []string{"http://localhost:9090/callback"},
				ResponseTypes:           []string{authlibtypes.ResponseTypeCode.String()},
				GrantTypes:              []string{authlibtypes.GrantTypeAuthorizationCode.String()},
				Scopes:                  []string{"offline_access", "profile"},
				TokenEndpointAuthMethod: authlibtypes.ClientNoneAuthentication.String(),
			},
			"confidential_client": {
				ClientName:              "Confidential client",
				ClientID:                "confidential_client",
				ClientSecret:            strings.ReplaceAll(uuid.New().String(), "-", ""),
				RedirectURIs:            []string{},
				ResponseTypes:           []string{authlibtypes.ResponseTypeCode.String()},
				GrantTypes:              []string{authlibtypes.GrantTypeAuthorizationCode.String()},
				Scopes:                  []string{"openid", "offline_access", "profile"},
				TokenEndpointAuthMethod: authlibtypes.ClientBasicAuthentication.String(),
			},
		},
	}

	m.mgr.Register(clientauth.NewNoneAuthHandler(m))
	m.mgr.Register(clientauth.NewBasicAuthHandler(m))
	m.mgr.Register(clientauth.NewPostAuthHandler(m))

	return m
}

// GetClient returns the raw *sql.Client for the given client ID, or nil if not found.
func (m *ClientManager) GetClient(id string) *sql.Client {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.clients[id]
}

// QueryByClientID retrieves an OAuth2 client by its client ID.
func (m *ClientManager) QueryByClientID(ctx context.Context, id string) (authlibmodels.Client, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	cl, ok := m.clients[id]
	if !ok {
		// Returning (nil, nil) signals authlib that the client was not found,
		// which causes it to respond with an invalid_request error to the caller.
		return nil, nil
	}

	return cl, nil
}

// Authenticate authenticates the client from the HTTP request using the registered auth methods.
func (m *ClientManager) Authenticate(r *http.Request, authMethods map[authlibtypes.ClientAuthMethod]bool, endpointName string) (authlibmodels.Client, error) {
	return m.mgr.Authenticate(r, authMethods, endpointName)
}

// CheckPermission reports whether the client is permitted to use the given token on the request.
func (m *ClientManager) CheckPermission(client authlibmodels.Client, token authlibmodels.Token, r *http.Request) bool {
	return true
}
