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
	"github.com/tniah/authlib/examples/assets"
	"github.com/tniah/authlib/examples/config"
	"github.com/tniah/authlib/examples/manager"
	"github.com/tniah/authlib/examples/middleware"
	integsql "github.com/tniah/authlib/integrations/sql"
	"github.com/tniah/authlib/rfc6749/ropc"
	authlibtypes "github.com/tniah/authlib/types"
)

//go:embed index.html static/app.js
var localAssets embed.FS

// SetupServer configures a Resource Owner Password Credentials grant server
// and returns an http.Handler with the following routes:
//
//   - GET /        — playground UI
//   - GET /static/ — static assets (CSS, JS)
//   - POST /token  — token endpoint
func SetupServer(_ *config.Config, lg *slog.Logger) (http.Handler, error) {
	clientMgr := manager.NewClientManager()
	demoClient := &integsql.Client{
		ClientID:                "ropc-demo-client",
		ClientName:              "Resource Owner Password Credentials Demo",
		ClientSecret:            "ropc-demo-secret",
		GrantTypes:              []string{"password"},
		Scopes:                  []string{"profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	clientMgr.Register(demoClient)

	userMgr := manager.NewUserManager()
	demoUser := &manager.User{
		UserID:   "a1ce0000-0000-4000-8000-000000000001",
		Username: "alice",
		Password: "secret",
	}
	userMgr.Register(demoUser)

	gt, err := ropc.Must(
		ropc.NewConfig().
			SetClientManager(clientMgr).
			SetUserManager(userMgr).
			SetTokenManager(manager.NewTokenManager()).
			SetSupportedClientAuthMethods(map[authlibtypes.ClientAuthMethod]bool{
				authlibtypes.ClientBasicAuthentication: true,
				authlibtypes.ClientPostAuthentication:  true,
			}),
	)
	if err != nil {
		return nil, err
	}

	srv := authlib.NewServer()
	srv.RegisterGrant(gt)

	clientJSON, _ := json.Marshal(map[string]interface{}{
		"client_id":                  demoClient.ClientID,
		"client_name":                demoClient.ClientName,
		"client_secret":              demoClient.ClientSecret,
		"token_endpoint_auth_method": demoClient.TokenEndpointAuthMethod,
		"scopes":                     demoClient.Scopes,
	})

	userJSON, _ := json.Marshal(map[string]interface{}{
		"username": demoUser.Username,
		"password": demoUser.Password,
	})

	// Pre-render index.html with client and user config injected as JS globals.
	rawHTML, _ := localAssets.ReadFile("index.html")
	injected := strings.Replace(
		string(rawHTML),
		"</head>",
		fmt.Sprintf("<script>window.__CLIENT__ = %s; window.__USER__ = %s;</script>\n</head>", clientJSON, userJSON),
		1,
	)

	mux := http.NewServeMux()

	// GET / — serve the playground UI with client config pre-injected.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(injected))
	})

	// GET /static/app.js — serve app-specific JS.
	appFS, _ := fs.Sub(localAssets, "static")
	mux.Handle("GET /static/app.js", http.StripPrefix("/static/", http.FileServer(http.FS(appFS))))

	// GET /static/ — serve shared assets (style.css, fonts.css, fonts/).
	sharedFS, _ := fs.Sub(assets.FS, "files")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(sharedFS))))

	// POST /token — token endpoint.
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := srv.CreateTokenResponse(r, w); err != nil {
			lg.Error("token request failed", "error", err)
		}
	})

	return middleware.AccessLog(lg)(mux), nil
}

// publicHost resolves the host used in public-facing URLs (redirect URIs, logs).
// 0.0.0.0 is a valid bind address but not a routable host, so it is mapped to localhost.
func publicHost(addr string) string {
	if addr == "0.0.0.0" {
		return "localhost"
	}
	return addr
}
