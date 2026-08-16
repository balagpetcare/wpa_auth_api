-- Additive OIDC registry/signing-key hardening.
-- Safe to apply without reset: it only introduces a new enum and nullable
-- columns required by the new client architecture and RSA signing-key
-- bootstrap path.

DO $$
BEGIN
  CREATE TYPE "OidcIdTokenSigningAlg" AS ENUM ('HS256', 'RS256');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE "auth_clients"
ADD COLUMN IF NOT EXISTS "oidc_id_token_signing_alg" "OidcIdTokenSigningAlg";

ALTER TABLE "oidc_signing_keys"
ADD COLUMN IF NOT EXISTS "private_key_encrypted" JSONB;
