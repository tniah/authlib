# Authlib

A modular OAuth 2.0 / OpenID Connect server library for Go, structured around RFC-named packages. Each package implements a specific specification and can be composed independently.

## Requirements

- Go 1.23+

## Installation

```bash
go get github.com/tniah/authlib
```

## Supported Specifications

| Specification  | Package                          | Description                              |
|----------------|----------------------------------|------------------------------------------|
| RFC 6749 §4.1  | `rfc6749/authorization_code`     | Authorization Code Grant                 |
| RFC 6749 §4.3  | `rfc6749/ropc`                   | Resource Owner Password Credentials      |
| RFC 6749 §2.3  | `rfc6749/client_authentication`  | Client authentication (`client_secret_basic`, `client_secret_post`, `none`)|
| RFC 6749       | `rfc6749/code_generator`         | Authorization code generation            |
| RFC 6750       | `rfc6750`                        | Bearer Token (opaque access + refresh)   |
| RFC 7636       | `rfc7636`                        | PKCE (Proof Key for Code Exchange)       |
| RFC 7662       | `rfc7662`                        | Token Introspection                      |
| RFC 9068       | `rfc9068`                        | JWT Access Tokens                        |
| OpenID Connect | `oidc/core/authorization_code`   | ID Token generation                      |

## Architecture

### Server

`Server` is the central dispatcher. Register grant flows and endpoints before use, then call its handler methods from your HTTP routes.

```go
srv := authlib.NewServer()
srv.RegisterGrant(authCodeFlow)
srv.RegisterGrant(ropcFlow)
srv.RegisterEndpoint(introspectionFlow)

// In your HTTP handlers:
srv.CreateAuthorizationResponse(r, w, user)  // GET  /authorize
srv.CreateConsentResponse(r, w, user)         // POST /authorize (consent step)
srv.CreateTokenResponse(r, w)                 // POST /token
srv.EndpointResponse(r, w, "introspection")  // POST /introspect
```

For finer control, use the split validate/respond methods:

```go
// Validate first — inspect the request before committing a response
grant, req, err := srv.ValidateAuthorizationRequest(r, user)
grant, req, err := srv.ValidateConsentRequest(r, user)
grant, req, err := srv.ValidateTokenRequest(r)
```

### Grant Flow Pattern

Every flow follows the same `Config` + `Flow` pattern:

```go
// 1. Build config
cfg := authorizationcode.NewConfig().
    SetClientManager(myClientManager).
    SetAuthCodeManager(myAuthCodeManager).
    SetTokenManager(myTokenManager)

// 2. Register optional extensions (PKCE, OIDC, etc.)
cfg.RegisterExtension(pkceFlow)
cfg.RegisterExtension(oidcFlow)

// 3. Instantiate — validates config, fails fast on missing dependencies
flow, err := authorizationcode.Must(cfg)

// 4. Register with server
srv.RegisterGrant(flow)
```

### Extension System

A single object can implement multiple extension interfaces and be registered once via `RegisterExtension`. Extensions are called in registration order.

| Interface                      | Called when                          |
|--------------------------------|--------------------------------------|
| `AuthorizationRequestValidator`| Validating `/authorize` request      |
| `ConsentRequestValidator`      | Validating the consent step          |
| `AuthCodeProcessor`            | Before saving the authorization code |
| `TokenRequestValidator`        | Validating `/token` request          |
| `TokenProcessor`               | Before writing the token response    |

PKCE (`rfc7636`) and OIDC (`oidc/core/authorization_code`) are implemented as extensions and plug into the Authorization Code flow via `RegisterExtension`.

## Usage

### Authorization Code + PKCE + OIDC

```go
import (
    "github.com/tniah/authlib"
    authorizationcode "github.com/tniah/authlib/rfc6749/authorization_code"
    "github.com/tniah/authlib/rfc7636"
    oidcflow "github.com/tniah/authlib/oidc/core/authorization_code"
)

// PKCE — plain and S256 both accepted by default (RFC 7636).
// To enforce S256-only per RFC 9700 §2.1, set AllowPlain to false.
pkce := rfc7636.New()

// PKCE with S256 enforced
pkce := rfc7636.New(
    rfc7636.NewOptions().SetAllowPlain(false),
)

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

### Resource Owner Password Credentials (RFC 6749 §4.3)

```go
import (
    "github.com/tniah/authlib"
    "github.com/tniah/authlib/rfc6749/ropc"
)

flow, _ := ropc.Must(
    ropc.NewConfig().
        SetClientManager(clientMgr).
        SetUserManager(userMgr).
        SetTokenManager(tokenMgr),
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
        SetAudience("https://api.example.com").
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

## Models

Implement the interfaces in the `models` package with your own data layer. See [`models/README.md`](models/README.md) for the full interface reference and [`integrations/sql/`](integrations/sql/) for example SQL-backed implementations.

## Package Documentation

| Package                                                                 | README                                                                   |
|-------------------------------------------------------------------------|--------------------------------------------------------------------------|
| `rfc6749/authorization_code`                                            | [README](rfc6749/authorization_code/README.md)                           |
| `rfc6749/ropc`                                                          | [README](rfc6749/ropc/README.md)                                         |
| `rfc6749/client_authentication`                                         | [README](rfc6749/client_authentication/README.md)                        |
| `rfc6749/code_generator`                                                | [README](rfc6749/code_generator/README.md)                               |
| `rfc6750`                                                               | [README](rfc6750/README.md)                                              |
| `rfc7636`                                                               | [README](rfc7636/README.md)                                              |
| `rfc7662`                                                               | [README](rfc7662/README.md)                                              |
| `rfc9068`                                                               | [README](rfc9068/README.md)                                              |
| `models`                                                                | [README](models/README.md)                                               |
| `integrations/sql`                                                      | [README](integrations/sql/README.md)                                     |
| `utils`                                                                 | [README](utils/README.md)                                                |

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
