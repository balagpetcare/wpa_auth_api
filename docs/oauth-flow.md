# OAuth / OIDC Flows — WPA Central Auth

Base URL: `http://localhost:5010/api/v1`

WPA Central Auth acts as the Authorization Server (AS) for all first-party and
third-party apps. Tokens are JWTs signed with HS256 (dev) or RS256 (production).

---

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/oauth/authorize` | GET | Issue authorization code (user must be authenticated) |
| `/oauth/token` | POST | Exchange code / refresh token / client credentials |
| `/oauth/userinfo` | GET | OIDC userinfo (bearer token required) |
| `/oauth/jwks` | GET | Public key set for token verification |
| `/oauth/introspect` | POST | Validate any token and return claims |
| `/oauth/revoke` | POST | Revoke refresh or service token |

---

## Flow 1: Furtail Mobile App Login (Authorization Code + PKCE)

Mobile apps are **public clients** (no `client_secret` stored on device). PKCE
prevents code interception attacks.

```
Client ID:    furtail_<hex>
Grant type:   authorization_code + PKCE
Redirect URI: furtail://auth/callback  (or https://furtail.com/auth/callback)
```

### Step 1 — User logs in to WPA Auth

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "emailOrUsername": "alice@example.com",
  "password": "SecurePass123!",
  "clientId": "furtail_<hex>"
}
```

Response contains `accessToken`. Store it in memory (not on disk).

### Step 2 — Request authorization code

Generate PKCE pair on device:

```
code_verifier  = random 43–128 char URL-safe string
code_challenge = BASE64URL(SHA256(code_verifier))
```

```http
GET /api/v1/oauth/authorize
  ?response_type=code
  &client_id=furtail_<hex>
  &redirect_uri=furtail://auth/callback
  &scope=openid%20profile%20email%20offline_access
  &state=<random-csrf-token>
  &code_challenge=<code_challenge>
  &code_challenge_method=S256
Authorization: Bearer <accessToken>
```

Response:
```json
{ "success": true, "code": "<opaque-code>", "state": "<state>" }
```

### Step 3 — Exchange code for tokens

```http
POST /api/v1/oauth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "client_id": "furtail_<hex>",
  "code": "<opaque-code>",
  "redirect_uri": "furtail://auth/callback",
  "code_verifier": "<original-code-verifier>"
}
```

Response:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid profile email offline_access",
  "user": { "id": "...", "email": "alice@example.com", "roles": ["user"] }
}
```

### Step 4 — Refresh when access token expires

```http
POST /api/v1/oauth/token
Content-Type: application/json

{
  "grant_type": "refresh_token",
  "client_id": "furtail_<hex>",
  "refresh_token": "eyJ..."
}
```

Refresh tokens are **rotated** on every use — store the new one and discard the old.

---

## Flow 2: BPA Website Login (Authorization Code, Confidential Client)

BPA runs a backend server that can safely store a `client_secret`.

```
Client ID:    bpa_<hex>
Client type:  FIRST_PARTY_APP (confidential)
Grant type:   authorization_code
```

### Step 1 — User logs in

Same as Furtail Step 1 but with BPA's `clientId`.

### Step 2 — Request authorization code

```http
GET /api/v1/oauth/authorize
  ?response_type=code
  &client_id=bpa_<hex>
  &redirect_uri=https://bpa.com/auth/callback
  &scope=openid%20profile%20email%20offline_access
  &state=<csrf>
Authorization: Bearer <accessToken>
```

### Step 3 — Exchange code (server-side, includes client_secret)

BPA's backend server makes this request — never from the browser:

```http
POST /api/v1/oauth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "client_id": "bpa_<hex>",
  "client_secret": "<raw-secret-from-setup>",
  "code": "<opaque-code>",
  "redirect_uri": "https://bpa.com/auth/callback"
}
```

Response is the same token envelope as Furtail.

### Step 4 — Verify a token (BPA backend validating a request)

```http
POST /api/v1/oauth/introspect
Content-Type: application/json

{
  "token": "eyJ...",
  "client_id": "bpa_<hex>",
  "client_secret": "<raw-secret>"
}
```

Response if active:
```json
{
  "active": true,
  "token_type": "Bearer",
  "sub": "<userId>",
  "email": "alice@example.com",
  "roles": ["user"],
  "exp": 1700000000,
  "iss": "http://localhost:5010"
}
```

---

## Flow 3: Payment Gateway Service-to-Service (client_credentials)

The Payment Gateway is a `SERVICE` client — no user is involved.

```
Client ID:    payment_gateway_<hex>
Client type:  SERVICE
Grant type:   client_credentials
```

### Step 1 — Obtain a service access token

Called from Payment Gateway's backend on startup or when token is about to expire:

```http
POST /api/v1/oauth/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": "payment_gateway_<hex>",
  "client_secret": "<raw-secret>",
  "scope": "payments:read payments:write refunds:write"
}
```

Response:
```json
{
  "access_token": "<opaque-service-token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "payments:read payments:write refunds:write"
}
```

### Step 2 — Other services validate the token via introspect

```http
POST /api/v1/oauth/introspect
Content-Type: application/json

{
  "token": "<opaque-service-token>",
  "client_id": "<calling-service-client-id>",
  "client_secret": "<calling-service-secret>"
}
```

Response if active:
```json
{
  "active": true,
  "token_type": "Bearer",
  "scope": "payments:read payments:write refunds:write",
  "client_id": "payment_gateway_<hex>",
  "exp": 1700003600
}
```

### Step 3 — Revoke a service token

```http
POST /api/v1/oauth/revoke
Content-Type: application/json

{
  "token": "<opaque-service-token>",
  "client_id": "payment_gateway_<hex>",
  "client_secret": "<raw-secret>"
}
```

Always returns `{ "success": true }` per RFC 7009 (even if token was not found).

---

## Security Notes

| Concern | Implementation |
|---|---|
| Authorization codes | Single-use, 10-minute TTL, stored as SHA-256 hash |
| PKCE | S256 method enforced for public clients (recommended) |
| Client secrets | Stored as SHA-256 hash, returned in plain only at creation/rotation |
| Refresh tokens | Rotated on every use; old token revoked atomically |
| Service tokens | Opaque tokens stored as SHA-256 hash, 1-hour TTL |
| Redirect URI | Must exactly match a registered URI — no prefix/wildcard matching |
| Scopes | Validated against `allowedScopes` on the AuthClient record |
| Audit | Every token issuance, authorization, introspection logged to `audit_logs` |

## Production Checklist

- [ ] Generate RSA-2048 key pair and set `JWT_RSA_PRIVATE_KEY` / `JWT_RSA_PUBLIC_KEY` (base64 PEM)
- [ ] Install `jose` package and implement real JWK export in `oauth.service.ts` (marked with TODO)
- [ ] Set `OAUTH_ISSUER` to the public HTTPS domain
- [ ] Register production `redirect_uri` values in the database for each client
- [ ] Replace in-memory rate limiter with Redis-backed limiter
- [ ] Add `/.well-known/openid-configuration` discovery endpoint
