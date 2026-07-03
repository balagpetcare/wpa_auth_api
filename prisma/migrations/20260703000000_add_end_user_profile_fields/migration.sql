-- AlterTable
ALTER TABLE "users" ADD COLUMN     "city" TEXT,
ADD COLUMN     "country" TEXT,
ADD COLUMN     "external_ref_id" TEXT,
ADD COLUMN     "failed_login_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "last_login_browser" TEXT,
ADD COLUMN     "last_login_device_type" TEXT,
ADD COLUMN     "last_login_ip" TEXT,
ADD COLUMN     "last_login_ip_country" TEXT,
ADD COLUMN     "last_login_os" TEXT,
ADD COLUMN     "registration_source" TEXT,
ADD COLUMN     "risk_score" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "state" TEXT,
ADD COLUMN     "timezone" TEXT;

-- CreateIndex
CREATE INDEX "users_last_seen_at_idx" ON "users"("last_seen_at");

-- CreateIndex
CREATE INDEX "users_country_idx" ON "users"("country");

-- CreateIndex
CREATE INDEX "users_state_idx" ON "users"("state");

-- CreateIndex
CREATE INDEX "users_city_idx" ON "users"("city");

-- CreateIndex
CREATE INDEX "users_timezone_idx" ON "users"("timezone");

-- CreateIndex
CREATE INDEX "users_external_ref_id_idx" ON "users"("external_ref_id");

-- CreateIndex
CREATE INDEX "users_registration_source_idx" ON "users"("registration_source");

-- CreateIndex
CREATE INDEX "users_email_verified_at_idx" ON "users"("email_verified_at");

-- CreateIndex
CREATE INDEX "users_phone_verified_at_idx" ON "users"("phone_verified_at");

-- CreateIndex
CREATE INDEX "users_last_login_ip_country_idx" ON "users"("last_login_ip_country");

-- CreateIndex
CREATE INDEX "users_risk_score_idx" ON "users"("risk_score");

-- CreateIndex
CREATE INDEX "users_failed_login_count_idx" ON "users"("failed_login_count");
