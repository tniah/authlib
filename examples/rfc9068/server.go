package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tniah/authlib"
	"github.com/tniah/authlib/examples/assets"
	"github.com/tniah/authlib/examples/config"
	"github.com/tniah/authlib/examples/manager"
	"github.com/tniah/authlib/examples/middleware"
	integsql "github.com/tniah/authlib/integrations/sql"
	"github.com/tniah/authlib/rfc6749/ropc"
	"github.com/tniah/authlib/rfc6750"
	"github.com/tniah/authlib/rfc9068"
	authlibtypes "github.com/tniah/authlib/types"
)

//go:embed index.html static/app.js keys/private.pem keys/public.pem
var localAssets embed.FS

// SetupServer configures a Resource Owner Password Credentials grant server
// with JWT access tokens (RFC 9068) and returns an http.Handler with the
// following routes:
//
//   - GET /        — playground UI
//   - GET /static/ — static assets (CSS, JS)
//   - POST /token  — token endpoint
func SetupServer(cfg *config.Config, lg *slog.Logger) (http.Handler, error) {
	clientMgr := manager.NewClientManager()
	demoClient := &integsql.Client{
		ClientID:                "jwt-demo-client",
		ClientName:              "JWT Access Tokens Demo",
		ClientSecret:            "jwt-demo-secret",
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

	issuer := fmt.Sprintf("http://%s:%s", publicHost(cfg.Address), cfg.Port)
	audience := "https://api.example.com"

	privPEM, err := localAssets.ReadFile("keys/private.pem")
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	pubPEM, err := localAssets.ReadFile("keys/public.pem")
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	jwtGen, err := rfc9068.MustJWTAccessTokenGenerator(
		rfc9068.NewGeneratorConfig().
			SetIssuer(issuer).
			SetAudience(audience).
			SetSigningKey(privPEM, jwt.SigningMethodRS256),
	)
	if err != nil {
		return nil, fmt.Errorf("jwt generator: %w", err)
	}

	bearerGen := rfc6750.NewBearerTokenGenerator(
		rfc6750.NewBearerTokenGeneratorOptions().SetAccessTokenGenerator(jwtGen),
	)

	gt, err := ropc.Must(
		ropc.NewConfig().
			SetClientManager(clientMgr).
			SetUserManager(userMgr).
			SetTokenManager(manager.NewTokenManagerWithGenerator(bearerGen)).
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

	jwtConfigJSON, _ := json.Marshal(map[string]interface{}{
		"issuer":     issuer,
		"audience":   audience,
		"algorithm":  "RS256",
		"public_key": strings.TrimSpace(string(pubPEM)),
	})

	// Pre-render index.html with client, user, and JWT config injected as JS globals.
	rawHTML, _ := localAssets.ReadFile("index.html")
	injected := strings.Replace(
		string(rawHTML),
		"</head>",
		fmt.Sprintf(
			"<script>window.__CLIENT__ = %s; window.__USER__ = %s; window.__JWT_CONFIG__ = %s;</script>\n</head>",
			clientJSON, userJSON, jwtConfigJSON,
		),
		1,
	)

	mux := http.NewServeMux()

	// GET / — serve the playground UI with config pre-injected.
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
