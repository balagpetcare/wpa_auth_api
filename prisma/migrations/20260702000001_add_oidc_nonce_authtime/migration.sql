-- Phase 2.5 (docs/phase-2-5-public-auth-rs256-oidc.md): OIDC id_token needs
-- to echo back the `nonce` the client sent at /oauth/authorize (replay
-- protection) and report `auth_time` (when the user actually authenticated).
-- Both are nullable/additive — no existing data affected.
ALTER TABLE "authorization_codes" ADD COLUMN "nonce" TEXT;
ALTER TABLE "authorization_codes" ADD COLUMN "auth_time" TIMESTAMP(3);
