ALTER TABLE "social_identity_provider_configs"
ADD COLUMN "provider_metadata" JSONB,
ADD COLUMN "last_test_at" TIMESTAMP(3),
ADD COLUMN "last_successful_test_at" TIMESTAMP(3),
ADD COLUMN "last_test_status" TEXT,
ADD COLUMN "last_test_error" TEXT;
