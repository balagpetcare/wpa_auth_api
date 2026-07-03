# WPA Central Auth Production Deployment Handoff

Branch: `final/central-auth-production-readiness`
Date: 2026-07-03

## Final objective status

- Central authentication system: Complete
- API objective: Complete
- Admin UI objective: Complete
- Production deployment readiness: Ready with accepted dependency risk

## Accepted dependency risks

- API: `prisma` 7.8.0 transitive `@prisma/dev` -> `@hono/node-server`, moderate, dev/build-toolchain only
- Auth Web: `next` -> `postcss`, moderate, production dependency, no safe non-breaking fix identified
- Admin UI: `next` -> `postcss`, moderate
- Admin UI: `next-auth` -> `uuid`, moderate
- Admin UI: `react-quill-new` -> `quill`, low

There were no unresolved Critical or High dependency issues in the final audit pass. A fully clean `npm audit --omit=dev` would require breaking framework/auth/editor upgrades or replacements.

## Production checklist

API deployment order:

1. `npm ci`
2. `npx prisma generate`
3. `npx prisma migrate deploy`
4. `npm run build`
5. Reload or start the API process with PM2

Auth Web deployment order:

1. `npm ci`
2. `npm run build`
3. Reload or start the web process with PM2

Admin UI deployment order:

1. `npm ci`
2. `npm run build`
3. Reload or start the admin process with PM2

Infrastructure checklist:

- Confirm Nginx reverse proxy routes the public auth and admin domains to the correct app processes
- Confirm HTTPS is enabled and cookies are marked `secure=true` in production
- Confirm trusted CORS origins include only production auth web and admin origins
- Confirm database backup is taken before migration deployment
- Confirm Redis is reachable before turning on production rate limiting
- Confirm logs are clean after first deployment
- Run smoke tests after each app deploy and again after the full stack is live

## Smoke test checklist

- Admin login works
- Auth Web user login works
- Register flow works if enabled
- Logout works
- Refresh/session persistence works
- Social provider order on the sign-in page is:
  - Primary: Google, Facebook, Apple, Microsoft
  - More: LinkedIn, TikTok, X, GitHub, Instagram
- Admin can enable/disable social providers
- Social provider public metadata API does not expose secrets
- OAuth callback with valid state succeeds
- OAuth callback with invalid or missing state fails safely
- Redirect and return URLs cannot target untrusted domains
- Admin RBAC blocks unauthorized provider management
- Build assets load correctly in light and dark theme

## Environment template notes

Required production variables should be documented without secrets:

- `NODE_ENV`
- `DATABASE_URL`
- `REDIS_URL`
- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `CREDENTIAL_ENCRYPTION_KEY`
- `COOKIE_DOMAIN`
- `ALLOWED_PUBLIC_ORIGINS`
- `APP_URL`
- `AUTH_WEB_URL`
- `ADMIN_PANEL_ORIGIN`
- `OAUTH_ISSUER`
- `JWT_RSA_PRIVATE_KEY` / `JWT_RSA_PUBLIC_KEY` if RS256 is enabled
- `RATE_LIMIT_LOGIN_WINDOW_MS`
- `RATE_LIMIT_LOGIN_MAX`
- `COMMUNICATION_RATE_LIMIT_ENABLED`
- `COMMUNICATION_MAX_PROVIDER_TEST_PER_ADMIN_HOUR`

No real secret values should ever be committed to this document or to `.env.example`.
