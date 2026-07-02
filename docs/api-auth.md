# Auth API — Request Examples

Base URL: `http://localhost:5010/api/v1`

All responses follow one of two shapes:

**Success**
```json
{ "success": true, ...payload }
```

**Error**
```json
{ "success": false, "message": "...", "code": "ERROR_CODE" }
```

---

## POST /auth/register

Register a new user. At least one of `email`, `phone`, or `username` is required.

```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "alice@example.com",
  "password": "SecurePass123!",
  "displayName": "Alice",
  "clientId": "wpa_central_<id>"
}
```

**201 Response**
```json
{
  "success": true,
  "user": {
    "id": "cuid...",
    "email": "alice@example.com",
    "username": null,
    "displayName": "Alice",
    "status": "PENDING_VERIFICATION",
    "roles": ["user"],
    "createdAt": "2026-06-30T00:00:00.000Z"
  }
}
```

---

## POST /auth/login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "emailOrUsername": "alice@example.com",
  "password": "SecurePass123!",
  "clientId": "wpa_central_<id>"
}
```

**200 Response**
```json
{
  "success": true,
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "expiresIn": 900,
  "user": { "id": "...", "email": "alice@example.com", "roles": ["user"], ... }
}
```

---

## POST /auth/refresh

Rotates the refresh token. Old token is revoked.

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJ..."
}
```

**200 Response** — same shape as login.

---

## POST /auth/logout

Requires `Authorization: Bearer <accessToken>`.

```http
POST /api/v1/auth/logout
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "refreshToken": "eyJ..."
}
```

**200 Response**
```json
{ "success": true, "message": "Logged out successfully." }
```

---

## GET /auth/me

Returns the current authenticated user.

```http
GET /api/v1/auth/me
Authorization: Bearer eyJ...
```

**200 Response**
```json
{
  "success": true,
  "user": { "id": "...", "email": "...", "roles": ["user"], ... }
}
```

---

## POST /auth/forgot-password

Always returns 200 to prevent user enumeration.

```http
POST /api/v1/auth/forgot-password
Content-Type: application/json

{
  "email": "alice@example.com"
}
```

**200 Response**
```json
{ "success": true, "message": "If that email exists, a reset link has been sent." }
```

---

## POST /auth/reset-password

The `token` is the opaque token delivered via email (see TODO in `auth.service.ts`).

```http
POST /api/v1/auth/reset-password
Content-Type: application/json

{
  "token": "<opaque-reset-token>",
  "password": "NewSecurePass456!"
}
```

**200 Response**
```json
{ "success": true, "message": "Password has been reset. Please log in with your new password." }
```

---

## POST /auth/verify-email/request

Requires authentication. Sends a verification token for the given email.

```http
POST /api/v1/auth/verify-email/request
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "email": "alice@example.com"
}
```

**200 Response**
```json
{ "success": true, "message": "Verification email sent." }
```

---

## POST /auth/verify-email/confirm

```http
POST /api/v1/auth/verify-email/confirm
Content-Type: application/json

{
  "token": "<opaque-verify-token>"
}
```

**200 Response**
```json
{ "success": true, "message": "Email verified successfully." }
```

---

## Error Codes

| Code                  | HTTP | Description                              |
|-----------------------|------|------------------------------------------|
| `VALIDATION_ERROR`    | 400  | Request body failed Zod validation       |
| `ALREADY_EXISTS`      | 409  | Email/phone/username already registered  |
| `INVALID_CREDENTIALS` | 401  | Wrong email or password                  |
| `ACCOUNT_SUSPENDED`   | 403  | Account is suspended                     |
| `ACCOUNT_INACTIVE`    | 403  | Account deleted or suspended on refresh  |
| `TOKEN_INVALID`       | 401  | JWT or opaque token is bad/expired       |
| `TOKEN_REVOKED`       | 401  | Refresh token was already revoked        |
| `ALREADY_VERIFIED`    | 400  | Email is already verified                |
| `NOT_FOUND`           | 404  | Resource not found                       |
| `RATE_LIMITED`        | 429  | Too many requests                        |
| `UNAUTHORIZED`        | 401  | Missing or malformed Authorization header|
| `INTERNAL_ERROR`      | 500  | Unexpected server error                  |

---

## Rate Limits (in-memory, single-process)

| Endpoint              | Limit         |
|-----------------------|---------------|
| POST /auth/login      | 10 / 15 min   |
| POST /auth/register   | 5 / 60 min    |
| POST /auth/forgot-password | 5 / 60 min |

> **Note:** Replace with Redis-backed limiter (`rate-limiter-flexible`) before production deployment.
