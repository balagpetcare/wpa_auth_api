-- Phase 3.7: key management and secret rotation foundation

ALTER TABLE "communication_provider_credentials"
ADD COLUMN IF NOT EXISTS "encryption_key_version" INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS "oidc_signing_keys" (
    "id" TEXT NOT NULL,
    "kid" TEXT NOT NULL,
    "public_key" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL DEFAULT 'RS256',
    "active" BOOLEAN NOT NULL DEFAULT TRUE,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "retired_at" TIMESTAMP(3),

    CONSTRAINT "oidc_signing_keys_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "oidc_signing_keys_kid_key" ON "oidc_signing_keys"("kid");
CREATE INDEX IF NOT EXISTS "oidc_signing_keys_active_created_at_idx" ON "oidc_signing_keys"("active", "created_at");
CREATE INDEX IF NOT EXISTS "oidc_signing_keys_kid_active_idx" ON "oidc_signing_keys"("kid", "active");
