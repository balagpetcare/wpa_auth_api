-- AlterTable
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "city" TEXT,
ADD COLUMN IF NOT EXISTS "country" TEXT,
ADD COLUMN IF NOT EXISTS "external_ref_id" TEXT,
ADD COLUMN IF NOT EXISTS "failed_login_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS "last_login_browser" TEXT,
ADD COLUMN IF NOT EXISTS "last_login_device_type" TEXT,
ADD COLUMN IF NOT EXISTS "last_login_ip" TEXT,
ADD COLUMN IF NOT EXISTS "last_login_ip_country" TEXT,
ADD COLUMN IF NOT EXISTS "last_login_os" TEXT,
ADD COLUMN IF NOT EXISTS "registration_source" TEXT,
ADD COLUMN IF NOT EXISTS "risk_score" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS "state" TEXT,
ADD COLUMN IF NOT EXISTS "timezone" TEXT;

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_last_seen_at_idx" ON "users"("last_seen_at");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_country_idx" ON "users"("country");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_state_idx" ON "users"("state");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_city_idx" ON "users"("city");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_timezone_idx" ON "users"("timezone");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_external_ref_id_idx" ON "users"("external_ref_id");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_registration_source_idx" ON "users"("registration_source");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_email_verified_at_idx" ON "users"("email_verified_at");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_phone_verified_at_idx" ON "users"("phone_verified_at");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_last_login_ip_country_idx" ON "users"("last_login_ip_country");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_risk_score_idx" ON "users"("risk_score");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "users_failed_login_count_idx" ON "users"("failed_login_count");
