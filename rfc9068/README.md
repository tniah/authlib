# rfc9068 — JWT Access Tokens (RFC 9068)

Package `rfc9068` implements [RFC 9068 — JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068). It provides `JWTAccessTokenGenerator`, a drop-in replacement for `rfc6750.OpaqueAccessTokenGenerator` that issues self-contained, signed JWTs instead of opaque random tokens.

## How It Works

```
+----------+              +--------------------+          +------------------+
|  Client  |              | Authorization      |          | Resource Server  |
+----------+              | Server             |          +------------------+
     |                    +--------------------+                  |
     |                             |                              |
     | (1) POST /token             |                              |
     |   grant_type, credentials   |                              |
     |---------------------------->|                              |
     |                             |                              |
     |                    (2) Authenticate client                 |
     |                        Validate request                    |
     |                             |                              |
     |                    (3) Generate JWT                        |
     |                        iss, sub, aud, exp                  |
     |                        iat, jti, client_id, scope          |
     |                        Sign with private key               |
     |                             |                              |
     | (4) 200 OK                  |                              |
     |   access_token: <JWT>       |                              |
     |<----------------------------|                              |
     |                             |                              |
     | (5) GET /resource           |                              |
     |   Authorization: Bearer <JWT>                              |
     |----------------------------------------------------------->|
     |                             |                              |
     | (6) 200 OK                  |                              |
     |<-----------------------------------------------------------|
     |                             |                              |
```

1. **Client sends a token request** to the `/token` endpoint with the appropriate grant type and credentials (e.g. `authorization_code`, `client_credentials`, `password`).
2. **Authorization server authenticates the client** and validates the request (grant type, redirect URI, scopes, etc.).
3. **`JWTAccessTokenGenerator.Generate` is called** — it intersects the requested scopes with the client's allowed scopes, assembles the RFC 9068 claim set (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, `scope`), merges any extra claims, and signs the result with the configured key.
4. **Authorization server returns `200 OK`** with `access_token` containing the signed JWT.
5. **Client calls the resource server** with `Authorization: Bearer <JWT>` header.
6. **Resource server validates the JWT** (signature, `exp`, `iss`, `aud`) and returns the protected resource.

## JWT Claims

| Claim | Required | Description |
|---|---|---|
| `iss` | ✅ | Issuer — authorization server URL |
| `sub` | ✅ | Subject — user ID, or `client_id` for client credentials |
| `aud` | ✅ | Audience — resource server identifier (e.g. `https://api.example.com`) |
| `exp` | ✅ | Expiration time |
| `iat` | ✅ | Issued-at time |
| `jti` | ✅ | JWT ID — random UUID without hyphens by default |
| `client_id` | ✅ | OAuth 2.0 client identifier |
| `scope` | when scopes granted | Space-separated list of granted scopes |

Extra claims can be added via `SetExtraClaimGenerator`. Protected claims above cannot be overridden.

The JWT header always carries `"typ": "at+JWT"` as required by RFC 9068 §2.1.

## Setup

```go
import (
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/tniah/authlib/rfc6750"
    "github.com/tniah/authlib/rfc9068"
)

generator, err := rfc9068.MustJWTAccessTokenGenerator(
    rfc9068.NewGeneratorConfig().
        SetIssuer("https://auth.example.com").
        SetAudience("https://api.example.com").
        SetSigningKey([]byte("your-secret-key"), jwt.SigningMethodHS256, "key-1").
        SetExpiresIn(time.Hour),
)
if err != nil {
    log.Fatal(err)
}
```

### Integration with Grant Flows

`JWTAccessTokenGenerator` satisfies the same `rfc6750.TokenGenerator` interface as `OpaqueAccessTokenGenerator`, so it plugs directly into `BearerTokenGenerator`:

```go
bearerGenerator, err := rfc6750.MustBearerTokenGenerator(
    rfc6750.NewBearerTokenGeneratorOptions().
        SetAccessTokenGenerator(generator),
)
```

Grant flows (`rfc6749/authorization_code`, `rfc6749/ropc`, etc.) are then configured with this `bearerGenerator` as their token manager — no other changes required.

## Config Options

| Method | Default | Description |
|---|---|---|
| `SetIssuer(iss string)` | — | Static `iss` claim value |
| `SetIssuerGenerator(fn)` | — | Dynamic issuer; overrides `SetIssuer` |
| `SetAudience(aud string)` | — | Static `aud` claim (resource server URL) |
| `SetAudienceGenerator(fn)` | — | Dynamic audience; overrides `SetAudience` |
| `SetExpiresIn(d time.Duration)` | `60m` | Static token lifetime |
| `SetExpiresInGenerator(fn)` | — | Dynamic lifetime; overrides `SetExpiresIn` |
| `SetSigningKey(key, method, kid...)` | — | Static signing key, algorithm, and optional key ID |
| `SetSigningKeyGenerator(fn)` | — | Dynamic signing key; overrides `SetSigningKey` |
| `SetExtraClaimGenerator(fn)` | — | Hook to add custom claims to the JWT payload |
| `SetJWTIDGenerator(fn)` | — | Custom `jti` generator; default is a random UUID |

Every static field has a dynamic generator counterpart. When both are set, the generator takes precedence.

## Dynamic Generators

### IssuerGenerator

```go
type IssuerGenerator func(ctx context.Context, client models.Client) string
```

Use for multi-tenant setups where the issuer URL varies per client.

```go
cfg.SetIssuerGenerator(func(ctx context.Context, client models.Client) string {
    return "https://" + client.GetTenantDomain() + "/oauth"
})
```

### AudienceGenerator

```go
type AudienceGenerator func(ctx context.Context, client models.Client) string
```

Use when the target resource server differs per client or per request.

```go
cfg.SetAudienceGenerator(func(ctx context.Context, client models.Client) string {
    return client.GetResourceServerURL()
})
```

### ExpiresInGenerator

```go
type ExpiresInGenerator func(ctx context.Context, grantType string, client models.Client) time.Duration
```

Use to apply per-client or per-grant-type expiry policies.

```go
cfg.SetExpiresInGenerator(func(ctx context.Context, grantType string, client models.Client) time.Duration {
    if grantType == "client_credentials" {
        return 15 * time.Minute
    }
    return time.Hour
})
```

### SigningKeyGenerator

```go
type SigningKeyGenerator func(ctx context.Context, client models.Client) ([]byte, jwt.SigningMethod, string, error)
```

Use for key rotation or per-client signing keys.

```go
cfg.SetSigningKeyGenerator(func(ctx context.Context, client models.Client) ([]byte, jwt.SigningMethod, string, error) {
    key, kid, err := keyStore.ActiveKey()
    return key, jwt.SigningMethodRS256, kid, err
})
```

### JWTIDGenerator

```go
type JWTIDGenerator func(ctx context.Context, grantType string, client models.Client) string
```

Use when you need a custom `jti` format (e.g. prefixed, database-tracked).

```go
cfg.SetJWTIDGenerator(func(ctx context.Context, grantType string, client models.Client) string {
    return "tok_" + uuid.NewString()
})
```

## Extra Claims

`ExtraClaimGenerator` adds application-specific claims (roles, tenant ID, etc.) to the JWT payload:

```go
type ExtraClaimGenerator func(
    ctx       context.Context,
    grantType string,
    client    models.Client,
    user      models.User,   // nil for client_credentials
    scopes    types.Scopes,
) (map[string]interface{}, error)
```

```go
cfg.SetExtraClaimGenerator(func(ctx context.Context, grantType string, client models.Client, user models.User, scopes types.Scopes) (map[string]interface{}, error) {
    if user == nil {
        return nil, nil
    }
    return map[string]interface{}{
        "roles":     getRoles(ctx, user.GetUserID()),
        "tenant_id": client.GetTenantID(),
    }, nil
})
```

### Protected Claims

The following standard claims **cannot be overridden** by `ExtraClaimGenerator`. Any key matching a protected claim is silently skipped:

`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, `scope`

## Validation Rules

`ValidateConfig` (called by `MustJWTAccessTokenGenerator`) enforces:

| Rule | Error |
|---|---|
| `issuer` or `issuerGenerator` must be set | `ErrMissingIssuer` |
| `audience` or `audienceGenerator` must be set | `ErrMissingAudience` |
| `expiresIn > 0` or `expiresInGenerator` must be set | `ErrMissingExpiresIn` |
| `signingKey` or `signingKeyGenerator` must be set | `ErrMissingSigningKey` |
| When `signingKey` is set, `signingKeyMethod` must not be nil | `ErrMissingSigningKeyMethod` |
| `signingKeyMethod` must not be `jwt.SigningMethodNone` | `ErrInsecureSigningMethod` |

The `none` algorithm check is also enforced at runtime when using `SigningKeyGenerator`, so a misconfigured generator cannot bypass it.

## Security Notes

- **`aud` must identify the resource server**, not the client. Setting `aud` to the client ID violates RFC 9068 §2.2 and breaks token audience validation at the resource server.
- **`none` algorithm is prohibited** by RFC 9068 §2.1. The library enforces this at both config validation and token generation time.
- **Use asymmetric keys in production** (RS256, ES256) so resource servers can validate tokens without access to the signing secret. Symmetric keys (HS256) require the signing secret to be shared with every resource server.
- **`sub` for client credentials** — when no user is present (e.g. `client_credentials` grant), `sub` is set to `client_id` per RFC 9068 §2.2.
