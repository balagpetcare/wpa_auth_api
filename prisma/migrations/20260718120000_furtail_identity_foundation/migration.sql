-- Furtail centralized-auth identity foundation (additive only).
-- Adds per-client audience/auth-method/token-policy columns to AuthClient,
-- normalized external-identity fields to OAuthAccount, and optional
-- device identifier/metadata columns to LoginSession/RefreshToken.
-- No existing tables are dropped, no existing rows are modified or deleted.

-- AlterTable
ALTER TABLE "auth_clients" ADD COLUMN     "access_token_ttl_seconds" INTEGER,
ADD COLUMN     "allowed_auth_methods" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "audience" TEXT,
ADD COLUMN     "refresh_token_ttl_seconds" INTEGER;

-- AlterTable
ALTER TABLE "login_sessions" ADD COLUMN     "device_id" TEXT,
ADD COLUMN     "device_info" JSONB;

-- AlterTable
ALTER TABLE "oauth_accounts" ADD COLUMN     "email" TEXT,
ADD COLUMN     "email_verified_at" TIMESTAMP(3),
ADD COLUMN     "last_login_at" TIMESTAMP(3),
ADD COLUMN     "phone" TEXT,
ADD COLUMN     "phone_verified_at" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "refresh_tokens" ADD COLUMN     "device_id" TEXT,
ADD COLUMN     "device_info" JSONB;

-- CreateIndex
CREATE UNIQUE INDEX "auth_clients_audience_key" ON "auth_clients"("audience");

-- CreateIndex
CREATE INDEX "login_sessions_device_id_idx" ON "login_sessions"("device_id");

-- CreateIndex
CREATE INDEX "oauth_accounts_email_idx" ON "oauth_accounts"("email");

-- CreateIndex
CREATE INDEX "oauth_accounts_phone_idx" ON "oauth_accounts"("phone");

-- CreateIndex
CREATE INDEX "refresh_tokens_device_id_idx" ON "refresh_tokens"("device_id");
