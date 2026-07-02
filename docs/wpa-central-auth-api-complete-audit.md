# WPA Central Auth API Complete Audit

Audit date: 2026-07-01 (investigation) — Phase 1 fixes applied 2026-07-01
Scope: `D:\wpa\wpa_auth\wpa_auth_api` (Express + TypeScript + Prisma + PostgreSQL)

---

## 1. Executive Summary

**Overall verdict after Phase 1 fixes: SIGNIFICANTLY IMPROVED — safe to begin Larkon Admin UI planning, with known gaps documented below.**

The core system is solid: `tsc --noEmit`, `npx prisma validate`, and `npm run build` all pass cleanly after every change in this pass. The auth flow (login/refresh/logout/me), RBAC, super-admin protection, rate limiting, audit logging, and admin invitation flow are genuinely implemented and reasonably well engineered (Redis-backed distributed rate limiting that fails closed in production is a notably mature choice). This is not a prototype — it has real, working thought behind session handling, graceful shutdown, and error-message hygiene (no stack trace leakage).

**Top security risks found (pre-fix):**
1. Unprotected duplicate route modules (`/clients`, `/roles`, `/audit`) allowed any authenticated user to create OAuth clients, rotate client secrets, create roles, and read the full audit log.
2. A duplicate `POST /admin/users/:id/reset-password` route definition silently shadowed the intended implementation.
3. Dead middleware (`clientValidation.ts`) contained a non-constant-time, hash-vs-plaintext secret comparison bug (unused, but a landmine if ever wired in).
4. `/oauth/jwks` is a non-functional stub — no real RFC 7517 JWKS export.
5. Non-super-admin roles (`ADMIN`, `SUPPORT`, `APP_MANAGER`, `SECURITY_AUDITOR`) receive zero permissions from the seed script, and there is no admin API to grant them any — permission-gated routes (communication, email management) are effectively unusable by anyone except `SUPER_ADMIN`.
6. `prisma/seed.ts` unconditionally created a hardcoded test account (`testuser@wpa.com` / `Password123!`) with no environment guard.
7. No PM2 process-manager config existed.
8. `.env.example` was missing the required `CREDENTIAL_ENCRYPTION_KEY`, and `.env.production.example` referenced a stale `JWT_ISSUER` name not read by `src/config/index.ts`.
9. No security-header middleware (helmet) was mounted.
10. 14 stale AI-generated markdown/txt session-summary files cluttered the repo root.

**What was fixed now (Phase 1, this pass):** Items 1, 2, 3 (mitigated), 6, 7, 8, 9, 10 above are fixed or mitigated. Item 4 (JWKS) and item 5 (permission assignment API) are intentionally **not** implemented in this pass per the Phase 1 scope — both are now clearly documented as blockers with inline `TODO`/warning comments in code and in this report (see §4, §6).

**What remains before the Larkon Admin UI rebuild:** a role→permission assignment API (§6), a real JWKS/RS256 implementation before any third-party app trusts this service as an OIDC identity provider (§4), and a decision on a single consistent JSON response envelope for non-OAuth endpoints (see §3 notes) before generating a typed frontend API client.

---

## 2. Project Overview

| Item | Value |
|---|---|
| Framework | Express 4.19 |
| Runtime | Node.js (ESM, `"type": "module"`) |
| Language | TypeScript 5.5, compiled via `tsc` |
| Package manager | npm (`package-lock.json` present) |
| Database | PostgreSQL |
| ORM | Prisma 7.8 (`@prisma/adapter-pg`) |
| Main entry (dev) | `src/server.ts` via `tsx watch` |
| Main entry (prod) | `dist/server.js` (`npm run build && npm start`) |
| API prefix | `/api/v1` (`config.API_PREFIX`), plus root-level `/health` |
| Env files | `.env` (live, gitignored), `.env.example`, `.env.local`, `.env.production.example` |
| Cache/queue | Redis (`ioredis`) — used for rate limiting only |
| Email | DB-driven `CommunicationProvider` system + custom template renderer + `EmailQueue` (not raw SMTP env vars) |
| Process manager | PM2 — `ecosystem.production.config.cjs` added this pass (previously missing) |
| Security headers | `helmet` — added and mounted this pass (previously missing) |

---

## 3. Route Inventory

Auth column: **Public** = no token required · **Auth** = `authGuard` (valid JWT) · **Admin** = `authGuard + requireAdmin` · **Perm** = additionally `requirePermission(...)`.

### `/api/v1/auth` — `src/modules/auth/auth.routes.ts`

| Method | Route | Auth Required | Permission/Role | Handler File | Status | Notes |
|---|---|---|---|---|---|---|
| POST | /auth/register | Public (rate-limited) | — | auth.service.ts | COMPLETE | |
| POST | /auth/login | Public (rate-limited) | — | auth.service.ts | COMPLETE | |
| POST | /auth/refresh | Public (rate-limited) | — | auth.service.ts | COMPLETE | |
| POST | /auth/logout | Auth | — | auth.service.ts | COMPLETE | |
| GET | /auth/me | Auth | — | auth.service.ts | COMPLETE | overlaps `/users/me` |
| POST | /auth/forgot-password | Public (rate-limited) | — | auth.service.ts | COMPLETE | always 200 (anti-enumeration) |
| POST | /auth/reset-password | Public (rate-limited) | — | auth.service.ts | COMPLETE | |
| POST | /auth/verify-email/request | Auth | — | auth.service.ts | COMPLETE | |
| POST | /auth/verify-email/confirm | Public | — | auth.service.ts | COMPLETE | |
| GET | /auth/admin-invitations/verify | Public | — | admin.service.ts | COMPLETE | |
| POST | /auth/admin-invitations/accept | Public | — | admin.service.ts | COMPLETE | |
| GET | /auth/social/providers | Public | — | social.service.ts | COMPLETE | |
| GET | /auth/social/:provider/start | Public (rate-limited) | — | social.service.ts | COMPLETE | |
| GET | /auth/social/:provider/callback | Public (rate-limited) | — | social.service.ts | COMPLETE | |
| POST | /auth/social/:provider/mobile | Public (rate-limited) | — | social.service.ts | COMPLETE | |

### `/api/v1/users` — `users.routes.ts`

| Method | Route | Auth Required | Permission/Role | Handler File | Status | Notes |
|---|---|---|---|---|---|---|
| GET | /users/me | Auth | — | users.routes.ts | COMPLETE | overlaps `/auth/me` |

### `/api/v1/admin/auth` — `admin.routes.ts` (`adminAuthRouter`)

| Method | Route | Auth Required | Permission/Role | Handler File | Status | Notes |
|---|---|---|---|---|---|---|
| POST | /admin/auth/login | Public (rate-limited) | rejects non-admin roles (403) | admin.routes.ts | COMPLETE | |
| GET | /admin/auth/me | Admin | — | admin.routes.ts | COMPLETE | |
| POST | /admin/auth/logout | Admin | — | admin.routes.ts | COMPLETE | |

### `/api/v1/admin/communication` — `communication.routes.ts` (router-level Admin)

| Method | Route | Auth Required | Permission/Role | Handler File | Status | Notes |
|---|---|---|---|---|---|---|
| GET/POST | /providers | Admin | Perm | communication.service.ts | COMPLETE | |
| GET/PATCH/DELETE | /providers/:id | Admin | Perm | communication.service.ts | COMPLETE | |
| POST | /providers/:id/activate\|deactivate\|test-sms\|test-email | Admin | Perm | communication.service.ts | COMPLETE | |
| POST | /providers/:id/credentials | Admin | Perm | communication.service.ts | COMPLETE | |
| PATCH | /providers/:id/credentials/:credentialId | Admin | Perm | communication.service.ts | COMPLETE | |
| GET/POST | /routing-rules | Admin | Perm | communication.service.ts | COMPLETE | |
| PATCH/DELETE | /routing-rules/:id | Admin | Perm | communication.service.ts | COMPLETE | |
| GET/POST | /templates | Admin | Perm | communication.service.ts | COMPLETE | |
| PATCH/DELETE | /templates/:id | Admin | Perm | communication.service.ts | COMPLETE | |
| GET | /delivery-logs, /provider-audit-logs, /provider-health | Admin | Perm | communication.service.ts | COMPLETE | |

### `/api/v1/admin` — `email.routes.ts` (router-level Admin)

| Method | Route | Auth Required | Permission/Role | Handler File | Status | Notes |
|---|---|---|---|---|---|---|
| GET/PATCH | /email-branding | Admin | Perm | email.routes.ts | COMPLETE | |
| GET | /email-templates | Admin | Perm | email.routes.ts | COMPLETE | |
| GET/PATCH | /email-templates/:id | Admin | Perm | email.routes.ts | COMPLETE | |
| POST | /email-templates/:id/preview\|send-test\|reset-default | Admin | Perm | email.routes.ts | COMPLETE | |
| GET | /email-templates/:id/versions | Admin | Perm | email.routes.ts | COMPLETE | |
| POST | /email-templates/:id/rollback/:versionId | Admin | Perm | email.routes.ts | COMPLETE | |
| POST | /email-templates/validate | Admin | Perm | email.routes.ts | COMPLETE | |
| GET/PATCH | /clients/:clientId/branding | Admin | Perm | email.routes.ts | COMPLETE | |
| GET | /email-send-logs | Admin | Perm | email.routes.ts | COMPLETE | |
| POST | /email-send-logs/:id/retry | Admin | Perm | email.routes.ts | COMPLETE | |
| GET | /email-queue | Admin | Perm | email.routes.ts | COMPLETE | |
| POST | /email-queue/process, /email-queue/:queueId/retry | Admin | Perm | email.routes.ts | COMPLETE | |

### `/api/v1/admin` — `admin.routes.ts` (router-level Admin)

| Method | Route | Auth Required | Permission/Role | Handler File | Status | Notes |
|---|---|---|---|---|---|---|
| GET | /users/summary, /users, /users/:id | Admin | Perm | admin.service.ts | COMPLETE | |
| PATCH | /users/:id/status, /users/:id | Admin | Perm | admin.service.ts | COMPLETE | |
| DELETE | /users/:id | Admin | Perm | admin.service.ts | COMPLETE | self-delete + last-super-admin guarded |
| POST | /users/:id/reset-password | Admin | Perm | admin.service.ts (`resetUserPasswordAdmin`) | **FIXED** | duplicate route removed this pass — see §5 |
| POST | /users/:id/revoke-sessions | Admin | Perm | admin.service.ts | COMPLETE | |
| GET | /users/:id/sessions, /users/:id/audit-logs | Admin | Perm | admin.service.ts | COMPLETE | |
| GET/POST | /roles | Admin | Perm | admin.service.ts | COMPLETE | protected version |
| PATCH | /roles/:id | Admin | Perm | admin.service.ts | COMPLETE | |
| GET | /permissions | Admin | Perm | admin.service.ts | COMPLETE | list only — still no role↔permission assignment endpoint (§6) |
| POST | /users/:id/roles | Admin | Perm | admin.service.ts | COMPLETE | |
| DELETE | /users/:id/roles/:roleId | Admin | Perm | admin.service.ts | COMPLETE | last-super-admin guarded |
| GET/POST | /clients | Admin | Perm | admin.service.ts | COMPLETE | protected version |
| GET/PATCH | /clients/:id | Admin | Perm | admin.service.ts | COMPLETE | |
| POST | /clients/:id/rotate-secret | Admin | Perm | admin.service.ts | COMPLETE | |
| PATCH | /clients/:id/status | Admin | Perm | admin.service.ts | COMPLETE | |
| GET | /audit-logs, /security-events | Admin | Perm | admin.service.ts | COMPLETE | protected version |
| GET | /dashboard/stats | Admin | Perm | admin.service.ts | COMPLETE | |
| GET/PATCH | /social-providers, /social-providers/:provider | Admin | Perm | admin.service.ts | COMPLETE | |
| GET/DELETE | /sessions, /sessions/:id | Admin | Perm | admin.service.ts | COMPLETE | |
| GET/DELETE | /oauth-accounts, /oauth-accounts/:id | Admin | Perm | admin.service.ts | COMPLETE | |
| GET | /settings | Admin | Perm | admin.service.ts | NEEDS VERIFICATION | confirm what "settings" contains |
| GET/PATCH | /account/me | Admin | — | admin.service.ts | COMPLETE | self-profile |
| POST/DELETE | /account/avatar | Admin | — | admin.service.ts | COMPLETE | multer, 2MB, jpeg/png/webp |
| POST | /account/change-password | Admin | — | admin.service.ts | COMPLETE | |
| GET | /notifications, /notifications/unread-count | Admin | — | admin.service.ts | COMPLETE | |
| PATCH | /notifications/read-all, /notifications/:id/read | Admin | — | admin.service.ts | COMPLETE | |
| DELETE | /notifications/:id | Admin | — | admin.service.ts | COMPLETE | |
| GET | /admin-users | Admin | Perm | admin.service.ts | COMPLETE | |
| POST | /admin-users/assign-existing | Admin | Perm | admin.service.ts | COMPLETE | |
| POST/GET | /admin-invitations | Admin | Perm | admin.service.ts | COMPLETE | |
| POST | /admin-invitations/:id/resend\|revoke | Admin | Perm | admin.service.ts | COMPLETE | |

### `/api/v1/oauth` — `oauth.routes.ts`

| Method | Route | Auth Required | Permission/Role | Handler File | Status | Notes |
|---|---|---|---|---|---|---|
| GET | /oauth/authorize | Auth (rate-limited) | — | oauth.service.ts | COMPLETE | PKCE supported |
| POST | /oauth/token | Public (rate-limited) | — | oauth.service.ts | COMPLETE | authorization_code/refresh_token/client_credentials |
| GET | /oauth/userinfo | Auth | — | oauth.service.ts | COMPLETE | OIDC-shaped response |
| GET | /oauth/jwks | Public | — | oauth.service.ts | **STUB — NOT PRODUCTION READY** | returns placeholder, not real JWKS; TODO comment added, see §4 |
| POST | /oauth/introspect | Public (rate-limited) | — | oauth.service.ts | COMPLETE | |
| POST | /oauth/revoke | Public (rate-limited) | — | oauth.service.ts | COMPLETE | |

### Legacy/unmounted duplicate modules — ⚠️ fixed this pass (previously security-relevant)

| Method | Route | Auth Required | Handler File | Status | Notes |
|---|---|---|---|---|---|
| POST/GET | /clients (top-level) | N/A — **unmounted** | clients.routes.ts | **FIXED (unmounted)** | router file kept for reference, marked legacy, `router.use('/clients', ...)` commented out in `src/routes/index.ts` |
| POST | /clients/:id/rotate-secret (top-level) | N/A — **unmounted** | clients.routes.ts | **FIXED (unmounted)** | see above |
| POST/GET | /roles (top-level) | N/A — **unmounted** | roles.routes.ts | **FIXED (unmounted)** | router file kept for reference, marked legacy, unmounted |
| GET | /audit (top-level) | N/A — **unmounted** | audit.routes.ts | **FIXED (unmounted)** | router file kept for reference, marked legacy, unmounted |

### Root-level (outside `/api/v1`)

| Method | Route | Auth Required | Handler File | Status | Notes |
|---|---|---|---|---|---|
| GET | /health | Public | server.ts | COMPLETE | shallow — no DB/Redis check; duplicated at `/api/v1/health` |
| GET | /uploads/avatars/* | Public (static) | server.ts | COMPLETE | now served with `helmet` cross-origin-resource-policy relaxation so it still loads from other allowed origins |

**Response format note:** the majority pattern across non-OAuth modules is `{ success: true, <resourceKey|data>: ... }` / `{ success: false, message, code }`. `oauth.routes.ts` deliberately deviates (RFC 6749/OIDC-shaped raw bodies) — this is intentional and should stay that way. The payload key name after `success` still varies by resource (`user`, `users`, `role`, `client`, `data`, etc.) — not changed in this pass (out of Phase 1 scope; a mechanical but breaking change best done deliberately before generating a typed Larkon API client).

---

## 4. Critical Findings

1. **Unsafe legacy `/clients`, `/roles`, `/audit` routes** — `src/modules/clients/clients.routes.ts`, `src/modules/roles/roles.routes.ts`, `src/modules/audit/audit.routes.ts` were mounted at top-level with only `authGuard` (no `requireAdmin`/`requirePermission`), letting any authenticated regular user create OAuth clients, rotate any client's secret, create roles, and read the entire audit log. Admin-safe equivalents already existed under `/admin/clients`, `/admin/roles` (role endpoints in `admin.routes.ts`), and `/admin/audit-logs`. **Status: FIXED** — unmounted from `src/routes/index.ts` (commented out with an explanatory note), and each module file now carries a top-of-file `⚠️ LEGACY / UNMOUNTED` warning comment so nobody re-enables them without adding proper guards.

2. **Duplicate admin route** — `POST /admin/users/:id/reset-password` was defined twice in `src/modules/admin/admin.routes.ts` (once calling `adminService.resetUserPasswordAdmin`, once calling `adminService.triggerPasswordReset`); the second silently shadowed the first at Express routing time. **Status: FIXED** — the second (shadowing) definition was removed. Decision: kept `resetUserPasswordAdmin` because it is the more complete implementation — it writes an audit log (`USER_PASSWORD_RESET_TRIGGERED`) **and** creates an `AdminNotification` for the affected user, whereas `triggerPasswordReset` only wrote an audit log and returned a placeholder message. `triggerPasswordReset` is left in `admin.service.ts` as unused dead code (not deleted, in case a future email-based reset flow wants it) but is no longer reachable from any route.

3. **Dead/insecure middleware** — `src/middleware/clientValidation.ts` was never imported by any route (confirmed via search across `src/routes` and `src/modules`), but contained a non-constant-time, hash-vs-plaintext secret comparison (`client.clientSecretHash !== clientSecret`) with an in-code comment literally documenting the author's uncertainty about how to compare it. **Status: MITIGATED** — replaced with a proper SHA-256 hash + `crypto.timingSafeEqual` comparison (`isValidClientSecret()`), consistent with how client secrets are actually hashed elsewhere (`clients.routes.ts`, `admin.service.ts`). A clear top-of-file warning marks the file as legacy/unused and states it must not be wired into production without a fresh security review.

4. **JWKS stub** — `src/modules/oauth/oauth.service.ts`'s `getJwks()` does not return a real RFC 7517 JWKS. Access/refresh tokens are always signed HS256 (`src/lib/tokens.ts`); even when `JWT_RSA_PUBLIC_KEY` is set, the RSA branch returns a placeholder object with no `n`/`e` modulus/exponent, so no third party can actually verify a signature via this endpoint. **Status: NOT IMPLEMENTED this pass (by design — full crypto rewrite is out of Phase 1 scope).** A clear `⚠️ NOT PRODUCTION READY` block comment was added directly above `getJwks()` explaining exactly what's missing and what must be done (sign with RS256 using `JWT_RSA_PRIVATE_KEY`, implement real JWK export via `jose`) before any third-party OIDC relying party is allowed to depend on this endpoint. **This is a hard blocker for using this service as a central IdP for other WPA apps, but it does NOT block the Larkon admin UI itself**, since the admin UI authenticates via the existing bearer-token flow, not JWKS-based verification.

5. **Permission assignment gap** — The seed script (`prisma/seed.ts`) creates 6 roles (`SUPER_ADMIN`, `ADMIN`, `SUPPORT`, `APP_MANAGER`, `SECURITY_AUDITOR`, `USER`) but maps **all** 25 seeded permissions only to `SUPER_ADMIN` (seed.ts lines ~81-93). There is no admin API endpoint to assign/revoke a permission on a role — `GET /admin/permissions` only lists permissions, there is no `POST /admin/roles/:id/permissions`. **Confirmed:** any user whose highest role is `ADMIN`/`SUPPORT`/`APP_MANAGER`/`SECURITY_AUDITOR` (not `SUPER_ADMIN`) currently **passes** `requireAdmin`-gated routes (role-name check only) but **fails every `requirePermission(...)`-gated route** — which includes the entire `communication.routes.ts` and `email.routes.ts` route sets — because `requirePermission` only bypasses its DB lookup for `super_admin` and otherwise requires an actual `RolePermission` row that doesn't exist for these roles. **Status: FIXED in Phase 2** (see §11 "Phase 2 Role-Permission API Update" below) — a full role→permission management API was added, and safe default read-only permissions (`roles:read`, `permissions:read`) were seeded to `ADMIN`.

6. **Seed test-user risk** — `prisma/seed.ts` previously created `testuser@wpa.com` / `Password123!` unconditionally whenever the seed ran and a `USER` role existed, with no environment guard — a real risk if the seed script is ever run against production (which is exactly when initial seeding tends to happen). **Status: FIXED** — wrapped in `if (process.env.NODE_ENV === 'production') { skip } else { create test user }`. Super-admin seeding logic (env-var driven, unaffected) was **not** touched or removed.

7. **Missing PM2 config** — No PM2 ecosystem config file existed anywhere in the repo. **Status: FIXED** — added `ecosystem.production.config.cjs` at repo root, app name `wpa-auth-api`, running `dist/server.js` (equivalent to `npm run start`), with `NODE_ENV: 'production'` set and an explicit comment that all secrets (DATABASE_URL, JWT secrets, CREDENTIAL_ENCRYPTION_KEY, REDIS_URL, etc.) must come from the deployment environment (real `.env`, systemd `EnvironmentFile`, or a secrets manager) — no secrets are hardcoded in the file.

8. **Root clutter** — 14 stale AI-generated markdown/txt session-summary files sat in the repo root. **Status: FIXED** — moved to `docs/archive/` (created new). `README.md` was left in root; no source, config, prisma, or env files were moved. See §5 for the full list.

9. **Env example drift** — `.env.example` was missing `CREDENTIAL_ENCRYPTION_KEY` (required by `src/config/index.ts`, min 32 chars — a fresh setup following the example alone would fail to boot). `.env.production.example` documented `JWT_ISSUER`, which is not read anywhere in `src/` (the actual config schema only defines `OAUTH_ISSUER`). **Status: FIXED** — `.env.example` now includes `CREDENTIAL_ENCRYPTION_KEY` with a clear 32+ character placeholder and comment, plus previously-undocumented vars (`APP_URL`, `ALLOWED_PUBLIC_ORIGINS`, `OAUTH_ISSUER`, OTP settings, JWKS/RSA notes, social provider placeholders). `.env.production.example` now uses `OAUTH_ISSUER` as the primary var (with `JWT_ISSUER` kept commented-out for historical reference only), adds `CREDENTIAL_ENCRYPTION_KEY`, and corrects the SMTP section to note that email delivery is actually DB-driven via the `CommunicationProvider` system, not raw `SMTP_*` env vars (those were commented out with an explanatory note rather than deleted).

10. **Missing security headers (helmet)** — No `helmet` (or manual CSP/HSTS/X-Frame-Options middleware) was present. **Status: FIXED** — `helmet` added as a dependency and mounted in `src/server.ts` before CORS and all routes, with `contentSecurityPolicy: false` (this is a JSON API, not an HTML-rendering server, so a page-oriented CSP isn't applicable and risked unexpected interference) and `crossOriginResourcePolicy: { policy: 'cross-origin' }` (so `/uploads/avatars` images continue to load correctly from other allowed origins, e.g. the admin panel). CORS behavior was not changed.

---

## 5. Fixes Applied

| Area | File | Change | Risk Reduced |
|---|---|---|---|
| Route protection | `src/routes/index.ts` | Removed imports and mount lines for `clientsRoutes`/`rolesRoutes`/`auditRoutes`; added explanatory comment block | Privilege escalation via unprotected `/clients`, `/roles`, `/audit` — CRITICAL → eliminated |
| Route protection | `src/modules/clients/clients.routes.ts` | Added top-of-file `⚠️ LEGACY / UNMOUNTED` warning comment | Prevents accidental re-mount without guards |
| Route protection | `src/modules/roles/roles.routes.ts` | Added top-of-file `⚠️ LEGACY / UNMOUNTED` warning comment | Prevents accidental re-mount without guards |
| Route protection | `src/modules/audit/audit.routes.ts` | Added top-of-file `⚠️ LEGACY / UNMOUNTED` warning comment | Prevents accidental re-mount without guards |
| Duplicate route | `src/modules/admin/admin.routes.ts` | Removed the second `POST /users/:id/reset-password` definition (`triggerPasswordReset`); kept the first (`resetUserPasswordAdmin`); added a comment documenting the decision | Removes silent route-shadowing bug; behavior is now deterministic |
| Insecure comparison | `src/middleware/clientValidation.ts` | Replaced `client.clientSecretHash !== clientSecret` with SHA-256 hash + `crypto.timingSafeEqual`; added top-of-file legacy/unused warning | Removes non-constant-time secret comparison and hash/plaintext mismatch bug, even though currently unused |
| JWKS documentation | `src/modules/oauth/oauth.service.ts` | Added explicit `⚠️ NOT PRODUCTION READY` block comment above `getJwks()` explaining the gap and required future work | No functional change; prevents silent misuse by future integrators |
| Seed safety | `prisma/seed.ts` | Wrapped hardcoded `testuser@wpa.com` creation in `if (process.env.NODE_ENV === 'production') { skip } else { ... }` | Removes risk of test credentials existing in a production database |
| Operational readiness | `ecosystem.production.config.cjs` (new) | Added PM2 config, app name `wpa-auth-api`, runs `dist/server.js`, no secrets hardcoded | Enables documented, repeatable production process management |
| Repo hygiene | `docs/archive/` (new) + 14 moved files | Moved `CHANGED_FILES.txt`, `EMAIL_INTEGRATION_COMPLETE.md`, `ENTERPRISE_EMAIL_IMPLEMENTATION.md`, `FINAL_PRE_DEPLOYMENT_REPORT.md`, `FINAL_SUMMARY.txt`, `IMPLEMENTATION_REPORT.md`, `INTEGRATION_SUMMARY.md`, `MIGRATION_FIX_REPORT.md`, `MULTI_CLIENT_EMAIL_AUDIT.md`, `MULTI_CLIENT_SUMMARY.md`, `PRODUCTION_FEATURES_SUMMARY.md`, `PRODUCTION_READINESS_REPORT.md`, `REMAINING_INTEGRATIONS.md`, `STARTUP_FIX_SUMMARY.md` out of repo root into `docs/archive/`; `README.md` left in place | Reduces repo-root noise ahead of Larkon rebuild; no functional risk |
| Env config | `.env.example` | Added `CREDENTIAL_ENCRYPTION_KEY` (32+ char placeholder), `APP_URL`, `ALLOWED_PUBLIC_ORIGINS`, `OAUTH_ISSUER`, OTP vars, JWKS/RSA notes, social provider placeholders, and a note on which vars are read outside the central config schema | Fresh setups following the example can now actually boot; documents drift |
| Env config | `.env.production.example` | Switched primary issuer var to `OAUTH_ISSUER` (kept `JWT_ISSUER` commented as historical reference), added `CREDENTIAL_ENCRYPTION_KEY`, corrected SMTP section to note DB-driven email delivery, added `APP_URL`/`ALLOWED_PUBLIC_ORIGINS` | Removes stale/misleading env guidance for production deploys |
| Security headers | `src/server.ts`, `package.json` | Added `helmet` dependency; mounted `helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } })` before CORS/routes | Adds baseline HTTP security headers (HSTS, X-Frame-Options, X-Content-Type-Options, etc.) with no observed behavior change to CORS or avatar serving |

---

## 6. Remaining API Gaps Before Larkon Admin UI

The following existing endpoints are stable and ready for the Larkon Admin UI to build against today:
- **Auth/session:** `POST /admin/auth/login`, `GET /admin/auth/me`, `POST /admin/auth/logout` — stable, admin-role-checked.
- **Dashboard:** `GET /admin/dashboard/stats` — implemented.
- **Users / admin-users:** `GET /admin/users*`, `GET /admin/admin-users`, `POST /admin/admin-users/assign-existing` — implemented, with last-super-admin and self-delete guards.
- **Roles/permissions (read-only):** `GET/POST/PATCH /admin/roles`, `GET /admin/permissions` — role CRUD works; **permission assignment does not** (see §4 finding 5 — this is a **blocker** for a functional "Roles & Permissions" UI page specifically; role listing/creation itself is fine).
- **Admin invitations:** `POST/GET /admin/admin-invitations`, resend/revoke, plus public accept/verify under `/auth/admin-invitations/*` — fully implemented.
- **Notifications:** `GET /admin/notifications*`, read/dismiss — implemented.
- **Email branding/templates:** `GET/PATCH /admin/email-branding`, full `/admin/email-templates*` CRUD + versioning/rollback/preview/send-test — implemented.
- **Communication providers:** `/admin/communication/*` — full CRUD, credentials, routing rules, delivery/audit logs, health — implemented.
- **Audit/security logs:** `GET /admin/audit-logs`, `GET /admin/security-events` — implemented (use these, not the now-unmounted `/audit`).
- **Account/profile/avatar:** `GET/PATCH /admin/account/me`, avatar upload/delete, change-password — implemented.

**What the Larkon Admin UI still needs before it can be fully functional:**
1. ~~A role→permission assignment API~~ — **DONE in Phase 2**, see §11. `GET/POST/PATCH/DELETE /admin/roles*` and `POST/PATCH/DELETE /admin/roles/:id/permissions*` are now implemented.
2. A decision on the standard JSON response envelope for non-OAuth routes before generating a typed API client (currently the payload key after `success` varies: `user`, `role`, `client`, `data`, etc.) — not a blocker, but will require per-endpoint special-casing in the frontend if left as-is.
3. Clarification of `GET /admin/settings` contents (flagged as "needs verification" in §3) before building a settings page around it.
4. A decision on which "current user" endpoint is canonical for the admin UI — `/admin/auth/me` is recommended, since `/auth/me` and `/users/me` are user-facing duplicates not scoped to admin context.

---

## 7. Security Audit

| Area | Risk Level | Finding | Status | Recommended Next Fix |
|---|---|---|---|---|
| Unprotected `/clients`, `/roles`, `/audit` routes | CRITICAL | Any authenticated non-admin user could create OAuth clients, rotate client secrets, create roles, read the full audit log | **FIXED** (unmounted) | None required; keep routers unmounted or add full admin guards before ever re-enabling |
| Hardcoded test credential in seed script | HIGH | `testuser@wpa.com` / `Password123!` created unconditionally | **FIXED** (NODE_ENV guard) | None required for Phase 1; consider removing entirely in Phase 3 if not needed even in dev |
| JWKS endpoint non-functional | HIGH | `/oauth/jwks` returns a placeholder, not a real JWK set | **DOCUMENTED, NOT FIXED** (by design, out of Phase 1 scope) | Implement real RS256 signing + `jose`-based JWK export (Phase 3) before any external relying party integrates |
| Permission assignment gap | HIGH (functional, not exploit) | Non-super-admin roles get zero permissions from seed; no API to grant any | **FIXED in Phase 2** — see §11 below | Re-run/verify seed on each environment (see §11) |
| Duplicate route shadowing | MEDIUM | `POST /admin/users/:id/reset-password` defined twice, second silently won | **FIXED** | None required |
| No security headers (helmet) | MEDIUM | No CSP/HSTS/X-Frame-Options/X-Content-Type-Options middleware | **FIXED** | None required; revisit CSP policy if the API ever serves HTML directly |
| Dead insecure code in `clientValidation.ts` | LOW (unused) | Non-constant-time secret comparison, unclear hash/plaintext semantics | **FIXED** (safe comparison + warning comment; file remains unused/unmounted) | None required unless this middleware is deliberately wired into a future service-to-service flow — re-review before doing so |
| `.env.example` missing required var | LOW | `CREDENTIAL_ENCRYPTION_KEY` absent, breaking fresh setups | **FIXED** | None required |
| Env schema / actual `.env` drift | LOW | Several `.env` keys not in the zod `envSchema` (legacy/unused) | **DOCUMENTED** in `.env.example`/`.env.production.example` comments | Consider pruning genuinely dead keys from the live `.env` in a future housekeeping pass |
| Shallow health check | LOW | `/health` doesn't verify DB/Redis connectivity | **NOT CHANGED** (out of Phase 1 scope) | Add a `/health/ready` deep check in Phase 2/3 |
| Self-suspend for non-super-admin | LOW | No server-side guard preventing an admin from suspending their own account | **NOT CHANGED** (out of Phase 1 scope) | Add explicit guard or document as UI-enforced only |
| Root clutter | LOW (hygiene) | 14 stale markdown/txt files in repo root | **FIXED** (moved to `docs/archive/`) | None required |
| Error handling / stack traces | none | `error.ts` never leaks stack traces or raw error messages to clients | Confirmed good, unchanged | No action needed |
| Rate limiting | none | Redis-backed, fails closed (503) in production if Redis is down | Confirmed good, unchanged | No action needed |
| Trust proxy | none | Off by default, explicit opt-in via `TRUST_PROXY` | Confirmed good, unchanged | No action needed |

---

## 8. Operational Readiness

- **Health endpoints:** `GET /health` (root) and `GET /api/v1/health` — both shallow (no DB/Redis connectivity check), unchanged in this pass. Recommend a deep `/health/ready` check in a future pass.
- **Redis requirement:** Required in production — `createRedisClient()` (`src/lib/redis.ts`) calls `process.exit(1)` if `REDIS_URL` is unset when `NODE_ENV=production`. Used exclusively for distributed rate limiting; the limiter itself fails closed (HTTP 503) if Redis becomes unreachable in production rather than silently bypassing protection.
- **PM2 readiness:** **Now ready** — `ecosystem.production.config.cjs` added at repo root (app name `wpa-auth-api`, runs `dist/server.js`, `NODE_ENV=production`, no hardcoded secrets — see §5). Deploy flow: `npm run build` then `pm2 start ecosystem.production.config.cjs --env production`.
- **Prisma validate:** `npx prisma validate` — **PASS** (see §9), both before and after all Phase 1 changes (no schema changes were made in this pass).
- **TypeScript check:** `npm run check` (`tsc --noEmit`) — **PASS** after all changes (see §9).
- **Build:** `npm run build` (`tsc`) — **PASS**, produces `dist/`.
- **Deployment env requirements:** `DATABASE_URL`, `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `CREDENTIAL_ENCRYPTION_KEY` (32+ chars), `REDIS_URL` are required to boot; `TRUST_PROXY` should be set to the correct hop count behind Nginx; SMTP/email is configured via the database (`CommunicationProvider` admin API), not env vars. See updated `.env.example` / `.env.production.example` for the full, corrected list.

---

## 9. Verification Results

All commands run from `D:\wpa\wpa_auth\wpa_auth_api` after Phase 1 changes were applied. No destructive commands were run (no `prisma migrate reset`, no `prisma db push`, no migration deletion).

**`npm run check` (tsc --noEmit):**
```
> wpa_auth_api@1.0.0 check
> tsc --noEmit
```
Result: **PASS** — no TypeScript errors.

**`npx prisma validate`:**
```
Loaded Prisma config from prisma.config.ts.
Prisma schema loaded from prisma\schema.prisma.
The schema at prisma\schema.prisma is valid 🚀
```
Result: **PASS**. No schema changes were made in this pass, so this was expected to remain green.

**`npm run build` (tsc):**
```
> wpa_auth_api@1.0.0 build
> tsc
```
Result: **PASS** — clean build, `dist/` regenerated with no errors, including the new `helmet` import in `src/server.ts`.

**`npm test`:** No `test` script exists in `package.json` — skipped per instructions (not run, not fabricated).

---

## 10. Next Safe AI Commands

1. "Design and implement a role→permission assignment API in `src/modules/admin/admin.routes.ts` + `admin.service.ts` (e.g. `POST /admin/roles/:id/permissions` and `DELETE /admin/roles/:id/permissions/:permissionId`), guarded by `requireAdmin` + an appropriate `requirePermission`, with audit logging consistent with the existing role-assignment endpoints. Do not change the existing `GET /admin/permissions` or `GET/POST/PATCH /admin/roles` behavior."

2. "Prepare a documented Larkon Admin UI API contract: for every `/admin/*` route in `src/modules/admin`, `src/modules/communication`, and `src/modules/email`, write down the exact request/response JSON shape actually returned today (not an idealized one), flag which ones use `data` vs a resource-named key, and propose a single normalized envelope migration plan as a separate, reviewable diff — do not apply the migration yet."

3. "Implement production-ready JWKS/RS256 OIDC support: install `jose`, generate or accept an RSA keypair via `JWT_RSA_PRIVATE_KEY`/`JWT_RSA_PUBLIC_KEY`, switch `src/lib/tokens.ts` access-token signing to RS256 when those keys are present (falling back to HS256 only if absent, with a clear startup log line stating which mode is active), and implement a real `getJwks()` in `src/modules/oauth/oauth.service.ts` that exports the correct `n`/`e`/`kid` from the public key. Keep all existing HS256 behavior working for deployments without RSA keys configured."

---

---

## 11. Phase 2 Role-Permission API Update

Implements the role→permission management API identified in §4 finding 5 / §7 as a blocker for the Larkon "Roles & Permissions" admin page. All existing auth/admin/email/communication behavior and all Phase 1 hardening changes were left intact — this is a strictly additive change.

### Endpoints added/updated (all under `/api/v1/admin`, router-level `authGuard, requireAdmin` unchanged)

| Method | Route | Guard | Status | Notes |
|---|---|---|---|---|
| GET | /admin/roles | `requirePermission('roles:read')` | **UPDATED** | Now returns each role's full `permissions` array and `userCount`, not just role metadata |
| GET | /admin/roles/:id | `requirePermission('roles:read')` | **NEW** | Single role with permissions + `userCount` |
| POST | /admin/roles | `requirePermission('roles:manage', 'roles:write')` | **UPDATED** | Now accepts optional `permissionIds`/`permissionKeys` at creation time; still validates unique role name; audit-logged (`ROLE_CREATED`) |
| PATCH | /admin/roles/:id | `requirePermission('roles:manage', 'roles:write')` | **UPDATED** | Can now optionally replace the role's full permission set in the same call; audit-logged (`ROLE_UPDATED`) |
| DELETE | /admin/roles/:id | `requirePermission('roles:manage', 'roles:delete')` | **NEW** | Blocks deleting `SUPER_ADMIN`; blocks deleting a role that still has assigned users (`409 ROLE_IN_USE`); audit-logged (`ROLE_DELETED`) |
| GET | /admin/permissions | `requirePermission('roles:read', 'permissions:read')` | **UPDATED** | Now returns `{ items: [...], groupedByResource: { <resource>: [...] } }` instead of a flat array, grouped by module/category as requested |
| POST | /admin/roles/:id/permissions | `requirePermission('roles:manage')` | **NEW** | Adds one or more permissions to a role (`permissionIds` and/or `permissionKeys`, deduplicated via `skipDuplicates`); audit-logged (`PERMISSION_GRANTED`) |
| PATCH | /admin/roles/:id/permissions | `requirePermission('roles:manage')` | **NEW** | Replaces the full permission set for a role inside a `prisma.$transaction`; validates every id/key resolves to a real `Permission` row before committing; audit-logged (`ROLE_UPDATED`, `metadata.replaced: true`) |
| DELETE | /admin/roles/:id/permissions/:permissionId | `requirePermission('roles:manage')` | **NEW** | Removes a single permission from a role; audit-logged (`PERMISSION_REVOKED`) |

Route definitions live in `src/modules/admin/admin.routes.ts` (Roles & Permissions section); all business logic lives in `src/modules/admin/admin.service.ts` (new/updated functions: `listRoles`, `getRoleById`, `createRole`/`createRoleAudited`, `updateRole`, `deleteRole`, `addPermissionsToRole`, `removePermissionFromRole`, `replaceRolePermissions`, `listPermissions`, plus internal helpers `resolvePermissions`, `formatRoleWithPermissions`, `assertCanModifySuperAdminPermissions`). No sensitive fields are exposed — role/permission responses only ever include `id`, `name`, `description`, `resource`, `action`, `createdAt`/`updatedAt`, and a computed `userCount`; there are no secret/hash fields on `Role` or `Permission` to accidentally leak.

### Permission keys used

Reused the existing `resource:action` colon-style naming already present in the seed (`roles:read`, `roles:write`) rather than introducing the dot-style convention used by the newer communication/email modules (`communication.providers.read`, etc.), for internal consistency within the `roles` resource. Added:
- `roles:delete` — role deletion
- `roles:manage` — the primary guard for all mutating role/permission-assignment routes (create, update, delete role; add/replace/remove permissions on a role)
- `permissions:read` — read the permission catalog

For backward compatibility, mutating role routes accept **either** `roles:manage` **or** the pre-existing `roles:write`/`roles:delete` (via `requirePermission('roles:manage', 'roles:write')`-style OR checks), so any role that already had `roles:write` from before this change keeps working without modification. `GET /admin/permissions` accepts either `roles:read` or the new `permissions:read`.

`requirePermission()` (`src/middleware/requirePermission.ts`) was **not modified** — its existing `super_admin` fast-path bypass (line 15-18) continues to grant `SUPER_ADMIN` unconditional access to every route above with no seed/DB permission row required, exactly as before.

### Guards added

- **Route-level:** every new/updated route above is gated by `authGuard` + `requireAdmin` (inherited from the router-level `router.use(authGuard, requireAdmin)` already in `admin.routes.ts`) plus the specific `requirePermission(...)` shown in the table.
- **SUPER_ADMIN protection (service-level, in `admin.service.ts`):**
  - `assertCanModifySuperAdminPermissions(roleName, actorRoles)` — throws `403 FORBIDDEN` if a non-`super_admin` actor attempts to change the **permission assignments** of the `SUPER_ADMIN` role (via `PATCH /roles/:id` with `permissionIds`/`permissionKeys`, `POST .../permissions`, `PATCH .../permissions`, or `DELETE .../permissions/:id`). Renaming/re-describing the `SUPER_ADMIN` role's `name`/`description` (no permission change) is still allowed for any admin holding `roles:manage`, since that alone doesn't affect access.
  - `deleteRole()` unconditionally rejects deleting the `SUPER_ADMIN` role, regardless of actor, with `403 FORBIDDEN`.
  - `updateRole()` and `replaceRolePermissions()` both reject attempts to reduce `SUPER_ADMIN`'s permission set to zero (`403 FORBIDDEN`, "Cannot remove all permissions from the SUPER_ADMIN role").
  - `removePermissionFromRole()` additionally guards against removing the *last remaining* permission from `SUPER_ADMIN` one-at-a-time (`403 FORBIDDEN` when `remaining <= 1`), preventing the same outcome via repeated single-permission removal calls.
  - `deleteRole()` also enforces "no users assigned" (`409 ROLE_IN_USE`) for any role, not just `SUPER_ADMIN`, per the task requirement.
  - **Last-super-admin protection is unaffected and untouched** — `guardLastSuperAdmin()` (used by `updateUserStatus`, `deleteUserAccount`, `removeRoleFromUser`) governs *user*-level super-admin removal and was not modified by this change; the new role-permission guards above are a separate, complementary layer that protects the `SUPER_ADMIN` *role definition itself* from being neutered.

### Seed changes (`prisma/seed.ts`)

- Added 3 new permissions to `permissionsList` (kept the pre-existing colon convention, decision documented inline in the seed file): `roles:delete`, `roles:manage`, `permissions:read`. `roles:read` and `roles:write` already existed and were **not duplicated**.
- `SUPER_ADMIN` role→permission mapping logic (maps 100% of permissions) was **not changed** — it automatically picks up the 3 new permissions on next seed run since it iterates `prisma.permission.findMany()`.
- Added a new step (2c) that grants `ADMIN` two safe, read-only default permissions: `roles:read` and `permissions:read`. This lets `ADMIN`-role users view roles/permissions in the Larkon UI without being able to create/update/delete roles or reassign permissions (those still require `roles:manage`/`roles:write`, granted only to `SUPER_ADMIN` by default). `SUPPORT` and `USER` were **intentionally left unchanged** (no roles/permissions access) per the task instruction not to over-permission them.
- **Operator action required:** these seed changes only take effect once the seed script is re-run. **This was not run automatically as part of this task** (per instructions, and because seeding is an idempotent-but-environment-specific operation the operator should control). Run:
  ```
  npm run prisma:seed
  ```
  (equivalently `npm run seed`) against each environment (dev/staging/production) that needs the new `roles:delete`/`roles:manage`/`permissions:read` permissions and the `ADMIN` default grants. The seed script is upsert-based and safe to re-run — it will not duplicate existing permissions/roles/clients and will not touch the hardcoded test-user guard added in Phase 1.

### Schema change (minimal, additive-only)

Three new `AuditAction` enum values were required for correct audit logging of role create/update/delete, since no existing enum value fit that specific semantic without causing misleading audit-log entries (existing `ROLE_ASSIGNED`/`ROLE_REMOVED` are already used elsewhere for *user*↔role assignment, not role CRUD). Reused unused-until-now `PERMISSION_GRANTED`/`PERMISSION_REVOKED` for permission-on-role add/remove (a perfect semantic fit, zero schema change needed for those two).

- `prisma/schema.prisma` — added `ROLE_CREATED`, `ROLE_UPDATED`, `ROLE_DELETED` to the `AuditAction` enum (additive-only, no data loss, no destructive statements).
- `prisma/migrations/20260701155004_add_role_management_audit_actions/migration.sql` — new migration file containing only:
  ```sql
  ALTER TYPE "AuditAction" ADD VALUE 'ROLE_CREATED';
  ALTER TYPE "AuditAction" ADD VALUE 'ROLE_UPDATED';
  ALTER TYPE "AuditAction" ADD VALUE 'ROLE_DELETED';
  ```
- **No migration command was run against any database in this pass** (no `prisma migrate dev`, no `prisma migrate deploy`, no `prisma db push`) — per instructions to avoid running migrations unless the schema change is absolutely required, and to avoid touching a database this task had no confirmed connectivity to. `npx prisma generate` **was** run (schema-only codegen, no DB connection, not a migration) so the TypeScript code compiles against the new enum values. **Operator action required:** run `npx prisma migrate deploy` (production) or `npx prisma migrate dev` (local/dev) before deploying this code, otherwise inserting an audit log row with `ROLE_CREATED`/`ROLE_UPDATED`/`ROLE_DELETED` will fail at runtime with a Postgres "invalid input value for enum" error until the migration is applied. The migration file follows the exact same `ALTER TYPE ... ADD VALUE` pattern as the four prior enum-extension migrations already in `prisma/migrations/`.

### Remaining limitations

- The new endpoints do not yet support pagination/filtering on `GET /admin/roles` (role count is small — 6 seeded roles — so this was judged unnecessary for Phase 2; revisit if the role list grows).
- `GET /admin/permissions`'s `groupedByResource` groups strictly by the existing `Permission.resource` column value (e.g. `roles`, `users`, `communication.providers`) — there is no separate human-friendly "category" field, so the grouping key is the raw resource string as already seeded.
- Role name uniqueness is checked case-sensitively (matches the existing `@unique` constraint on `Role.name` — not changed).
- The audit-log migration above must be applied by the operator before role-CRUD audit logging will function in a given environment (see previous section) — until then, `POST/PATCH/DELETE /admin/roles*` will throw a 500 error rather than silently skip the audit log, since `writeAuditLog` is awaited and not wrapped in a try/catch (consistent with how audit logging is treated as non-optional everywhere else in this codebase).
- This pass did not touch the still-open Phase 1 items: JWKS/RS256 (§4 finding 4) and the standard response-envelope decision (§3 note, §6 item 2) remain outstanding.

### Larkon UI readiness status for Roles & Permissions page

**Ready to build.** The Larkon "Roles & Permissions" admin page can now be built against a complete API surface:
- List roles with their permissions and user counts (`GET /admin/roles`).
- View/edit a single role, including replacing its permission set (`GET /admin/roles/:id`, `PATCH /admin/roles/:id`).
- Create a new role with an initial permission set (`POST /admin/roles`).
- Delete a role (with clear, actionable error messages when blocked by `SUPER_ADMIN` protection or existing user assignments) (`DELETE /admin/roles/:id`).
- Browse the full permission catalog grouped by module (`GET /admin/permissions`).
- Add/remove/replace individual permissions on a role without resending the whole set (`POST`/`DELETE`/`PATCH /admin/roles/:id/permissions*`).

**Before this is usable end-to-end in a real environment**, the operator must (1) run the new migration (`prisma migrate deploy`/`dev`) and (2) re-run the seed script (`npm run prisma:seed`) as documented above — otherwise the new permission keys won't exist in the database and role-CRUD audit logging will fail. Both are one-time, safe, idempotent operator actions, not additional development work.

---

*Files changed in this pass are listed in the final assistant response. Report authored and verified 2026-07-01. Phase 2 role-permission API update appended 2026-07-01.*
