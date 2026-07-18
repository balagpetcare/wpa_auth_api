-- Furtail centralized-auth: enterprise identity provider config + bootstrap
-- config fields. Purely additive (new enum value, new nullable/defaulted
-- columns, new table) — no drops, no destructive changes. Existing clients
-- (BPA) are unaffected: required_profile_fields defaults to an empty array
-- (no extra requirement) and registration_open defaults to true (unchanged
-- behavior).

-- CreateEnum
CREATE TYPE "EnterpriseIdentityProtocol" AS ENUM ('OIDC', 'SAML');

-- AlterEnum: add ENTERPRISE as a new OAuthProvider value (additive).
ALTER TYPE "OAuthProvider" ADD VALUE IF NOT EXISTS 'ENTERPRISE';

-- AlterTable
ALTER TABLE "auth_clients"
  ADD COLUMN IF NOT EXISTS "required_profile_fields" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN IF NOT EXISTS "registration_open" BOOLEAN NOT NULL DEFAULT true;

-- CreateTable
CREATE TABLE IF NOT EXISTS "enterprise_identity_providers" (
    "id" TEXT NOT NULL,
    "org_slug" TEXT NOT NULL,
    "display_name" TEXT NOT NULL,
    "protocol" "EnterpriseIdentityProtocol" NOT NULL DEFAULT 'OIDC',
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "issuer" TEXT,
    "client_id" TEXT,
    "client_secret_encrypted" TEXT,
    "jwks_uri" TEXT,
    "authorization_url" TEXT,
    "token_url" TEXT,
    "redirect_uri" TEXT,
    "metadata_url" TEXT,
    "entity_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "enterprise_identity_providers_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "enterprise_identity_providers_org_slug_key" ON "enterprise_identity_providers"("org_slug");
CREATE INDEX IF NOT EXISTS "enterprise_identity_providers_org_slug_idx" ON "enterprise_identity_providers"("org_slug");
CREATE INDEX IF NOT EXISTS "enterprise_identity_providers_enabled_protocol_idx" ON "enterprise_identity_providers"("enabled", "protocol");
