-- Additive: single-use PKCE-bound authorization codes for mobile
-- social/enterprise login completion. No existing tables are touched.
CREATE TABLE "mobile_authorization_codes" (
    "id" TEXT NOT NULL,
    "code_hash" TEXT NOT NULL,
    "client_db_id" TEXT NOT NULL,
    "redirect_uri" TEXT NOT NULL,
    "code_challenge" TEXT NOT NULL,
    "payload_encrypted" TEXT NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "consumed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "mobile_authorization_codes_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "mobile_authorization_codes_code_hash_key" ON "mobile_authorization_codes"("code_hash");
CREATE INDEX "mobile_authorization_codes_expires_at_idx" ON "mobile_authorization_codes"("expires_at");
