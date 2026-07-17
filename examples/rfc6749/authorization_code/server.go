package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tniah/authlib"
	"github.com/tniah/authlib/examples/manager"
	"github.com/tniah/authlib/examples/middleware"
	authcodegrant "github.com/tniah/authlib/rfc6749/authorization_code"
)

//go:embed index.html static
var assets embed.FS

// SetupServer configures an Authorization Code grant server and returns an
// http.Handler with the following routes:
//
//   - GET /           — playground UI
//   - GET /static/    — static assets (CSS, JS)
//   - GET /authorize  — authorization endpoint
//   - POST /token     — token endpoint
func SetupServer(lg *slog.Logger) (http.Handler, error) {
	clientMgr := manager.NewClientManager()

	gt, err := authcodegrant.Must(
		authcodegrant.NewConfig().
			SetClientManager(clientMgr).
			SetUserManager(manager.NewUserManager()).
			SetAuthCodeManager(manager.NewAuthorizationCodeManager()).
			SetTokenManager(manager.NewTokenManager()),
	)
	if err != nil {
		return nil, err
	}

	srv := authlib.NewServer()
	srv.RegisterGrant(gt)

	// Read client data once at startup directly from the manager.
	publicClient := clientMgr.GetClient("public_client")
	clientJSON, _ := json.Marshal(map[string]interface{}{
		"client_id":                  publicClient.ClientID,
		"client_name":                publicClient.ClientName,
		"redirect_uris":              publicClient.RedirectURIs,
		"response_types":             publicClient.ResponseTypes,
		"token_endpoint_auth_method": publicClient.TokenEndpointAuthMethod,
		"scopes":                     publicClient.Scopes,
	})

	// Pre-render index.html with the client config injected as a JS global.
	rawHTML, _ := assets.ReadFile("index.html")
	injected := strings.Replace(
		string(rawHTML),
		"</head>",
		fmt.Sprintf("<script>window.__CLIENT__ = %s;</script>\n</head>", clientJSON),
		1,
	)

	mux := http.NewServeMux()

	// GET / — serve the playground UI with client config pre-injected.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(injected))
	})

	// GET /static/ — serve CSS, JS, and other static assets.
	staticFS, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// GET /authorize — authorization endpoint.
	// In a real application, retrieve the authenticated user from the session.
	// For this example, alice is used to simulate a logged-in session.
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		alice := &manager.User{UserID: "usr_alice001", Username: "alice"}
		if err := srv.CreateAuthorizationResponse(r, w, alice); err != nil {
			lg.Error("authorization request failed", "error", err, "client_id", r.URL.Query().Get("client_id"))
		}
	})

	// POST /token — token endpoint.
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := srv.CreateTokenResponse(r, w); err != nil {
			lg.Error("token request failed", "error", err)
		}
	})

	return middleware.AccessLog(lg)(mux), nil
}
