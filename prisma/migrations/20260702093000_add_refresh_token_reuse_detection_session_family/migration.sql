-- Additive Phase 3.2 migration for refresh-token reuse detection and session family revocation.

ALTER TABLE IF EXISTS "refresh_tokens"
  ADD COLUMN IF NOT EXISTS "family_id" TEXT,
  ADD COLUMN IF NOT EXISTS "replaced_by_token_id" TEXT,
  ADD COLUMN IF NOT EXISTS "reused_at" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "revocation_reason" TEXT;

CREATE INDEX IF NOT EXISTS "refresh_tokens_family_id_idx"
  ON "refresh_tokens" ("family_id");

ALTER TABLE IF EXISTS "login_sessions"
  ADD COLUMN IF NOT EXISTS "revocation_reason" TEXT;
