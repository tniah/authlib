# Authlib

A modular OAuth 2.0 / OpenID Connect server library for Go, structured around RFC-named packages. Each package implements a specific specification and can be composed independently.

## Requirements

- Go 1.23+

## Installation

```bash
go get github.com/tniah/authlib
```

## Features

| Specification | Package | Description |
|---------------|---------|-------------|
| RFC 6749 §4.1 | `rfc6749/authorization_code` | Authorization Code Grant |
| RFC 6749 §4.3 | `rfc6749/ropc` | Resource Owner Password Credentials |
| RFC 6749 §6 | `rfc6749/refresh_token` | Refresh Token Grant |
| RFC 6750 | `rfc6750` | Bearer Token (opaque access + refresh tokens) |
| RFC 7636 | `rfc7636` | PKCE (Proof Key for Code Exchange) |
| RFC 7662 | `rfc7662` | Token Introspection |
| RFC 9068 | `rfc9068` | JWT Access Tokens |
| OpenID Connect | `oidc/core/authorization_code` | ID Token generation |

## Architecture

### Server

`Server` is the central dispatcher. Register grant flows and endpoints before use, then call its handler methods from your HTTP routes.

```go
srv := authlib.NewServer()
srv.RegisterGrant(authCodeFlow)
srv.RegisterGrant(ropcFlow)
srv.RegisterEndpoint(introspectionFlow)

// In your HTTP handlers:
srv.CreateAuthorizationResponse(r, w, user)   // /authorize
srv.CreateConsentResponse(r, w, user)          // /authorize (consent step)
srv.CreateTokenResponse(r, w)                  // /token
srv.EndpointResponse(r, w, "introspection")   // /introspect
```

### Grant Flow Pattern

Each flow follows the same `Config` + `Flow` pattern:

```go
// 1. Build config
cfg := authorizationcode.NewConfig().
    SetClientManager(myClientManager).
    SetAuthCodeManager(myAuthCodeManager).
    SetTokenManager(myTokenManager)

// 2. Register optional extensions (PKCE, OIDC, etc.)
cfg.RegisterExtension(pkceFlow)
cfg.RegisterExtension(oidcFlow)

// 3. Instantiate (validates config)
flow, err := authorizationcode.Must(cfg)

// 4. Register with server
srv.RegisterGrant(flow)
```

### Extension System

A single object can implement multiple extension interfaces and be registered once. Extensions are executed in registration order.

```go
type MyExtension struct{}

func (e *MyExtension) ValidateAuthorizationRequest(r *requests.AuthorizationRequest) error { ... }
func (e *MyExtension) ValidateTokenRequest(r *requests.TokenRequest) error { ... }

cfg.RegisterExtension(&MyExtension{})
```

Extension interfaces per flow:

| Interface | Called when |
|-----------|-------------|
| `AuthorizationRequestValidator` | Validating `/authorize` request |
| `ConsentRequestValidator` | Validating consent step |
| `AuthCodeProcessor` | Before saving authorization code |
| `TokenRequestValidator` | Validating `/token` request |
| `TokenProcessor` | Before sending token response |

## Usage

### Authorization Code + PKCE + OIDC

```go
import (
    "github.com/tniah/authlib"
    authorizationcode "github.com/tniah/authlib/rfc6749/authorization_code"
    "github.com/tniah/authlib/rfc7636"
    oidcflow "github.com/tniah/authlib/oidc/core/authorization_code"
)

// PKCE (S256 by default, per RFC 9700)
pkce := rfc7636.New()

// OIDC ID Token
oidc, _ := oidcflow.Must(
    oidcflow.NewConfig().
        SetIssuer("https://auth.example.com").
        SetSigningKey(privateKey, jwt.SigningMethodRS256, "key-1"),
)

// Authorization Code flow
flow, _ := authorizationcode.Must(
    authorizationcode.NewConfig().
        SetClientManager(clientMgr).
        SetAuthCodeManager(authCodeMgr).
        SetTokenManager(tokenMgr).
        RegisterExtension(pkce).
        RegisterExtension(oidc),
)

srv := authlib.NewServer()
srv.RegisterGrant(flow)
```

### JWT Access Tokens (RFC 9068)

```go
import "github.com/tniah/authlib/rfc9068"

jwtGen, _ := rfc9068.MustJWTAccessTokenGenerator(
    rfc9068.NewGeneratorConfig().
        SetIssuer("https://auth.example.com").
        SetSigningKey(privateKey, jwt.SigningMethodRS256, "key-1"),
)
```

### Token Introspection (RFC 7662)

```go
import "github.com/tniah/authlib/rfc7662"

introspection, _ := rfc7662.MustTokenIntrospectionFlow(
    rfc7662.NewConfig().
        SetClientManager(clientMgr).
        SetTokenManager(tokenMgr),
)

srv.RegisterEndpoint(introspection)

// Handle: POST /introspect
srv.EndpointResponse(r, w, "introspection")
```

### Custom Error Handler

```go
srv.RegisterErrorHandler(func(r *http.Request, w http.ResponseWriter, err error) error {
    // custom logging, formatting, etc.
    return nil
})
```

## Implementing Required Interfaces

Implement the interfaces in the `models` package with your own data layer:

```go
// models.Client — your OAuth2 client entity
type Client interface {
    GetClientID() string
    CheckClientSecret(secret string) bool
    CheckGrantType(gt types.GrantType) bool
    CheckRedirectURI(uri string) bool
    GetAllowedScopes(scopes types.Scopes) types.Scopes
    // ...
}

// models.Token — your access/refresh token entity
type Token interface {
    GetAccessToken() string
    GetRefreshToken() string
    GetUserID() string
    GetClientID() string
    GetScopes() types.Scopes
    GetIssuedAt() time.Time
    GetAccessTokenExpiresIn() time.Duration
    // ...
}
```

See `integrations/sql/` for example SQL-based implementations.

## Running Tests

```bash
# All tests
go test ./...

# Specific package
go test ./rfc6749/authorization_code/...

# Single test
go test -run TestFunctionName ./path/to/package/...
```

## Regenerating Mocks

Mocks are generated with [mockery](https://github.com/vektra/mockery). Configuration is in `.mockery.yaml`.

```bash
mockery
```

## License

MIT
