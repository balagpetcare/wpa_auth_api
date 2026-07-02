# Security Hardening for WPA Central Auth Phase 3

Branch: `security/central-auth-phase-3-hardening`

Commit: `28b367e`

Remote: `https://github.com/balagpetcare/wpa_auth_api.git`

## Completed Work

Phase 1 to Phase 3.2 coverage includes:
- stabilized and secured the auth bootstrap and token lifecycle
- connected admin users, RBAC, notifications, and dashboard shell flows
- aligned the admin UI to real API endpoints
- replaced placeholder service-token behavior with a clear API-required state
- fixed expired and invalid token handling
- implemented RS256 OIDC `id_token` signing support
- added app-aware communication routing and provider controls
- implemented refresh-token reuse detection and session-family revocation
- added enterprise anti-bot and abuse-protection foundations

## Security Improvements

- canonical token storage uses:
  - `wpa_auth_access_token`
  - `wpa_auth_refresh_token`
- invalid or expired tokens are cleared cleanly
- refresh-token reuse is detected and escalates to session-family revocation
- Redis-backed rate limiting and temporary blocklists are in place for auth and OAuth abuse paths
- admin login is stricter than public auth login
- sensitive admin actions write audit/security/notification records
- secret-bearing scratch files were removed from the repo

## Migrations Included

- `20260701111531_add_email_branding_and_templates`
- `20260701111546_add_email_branding_and_templates`
- `20260701155004_add_role_management_audit_actions`
- `20260702000001_add_oidc_nonce_authtime`
- `20260702010000_add_app_aware_routing_and_replyto`
- `20260702093000_add_refresh_token_reuse_detection_session_family`

## Verification

Passed:
- `npx prisma validate`
- `npx tsc --noEmit`
- `npm run build`

## Remaining Gaps

- CAPTCHA client UX is still a future phase item
- additional security event dashboards can be added later
- some non-core informational pages remain template-like and are not part of the auth/security core
