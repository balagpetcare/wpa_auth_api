-- CreateEnum
CREATE TYPE "CommunicationChannel" AS ENUM ('SMS', 'EMAIL');

-- CreateEnum
CREATE TYPE "CommunicationProviderStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'TESTING', 'DISABLED');

-- CreateEnum
CREATE TYPE "CommunicationProviderEnvironment" AS ENUM ('SANDBOX', 'LIVE');

-- CreateEnum
CREATE TYPE "CommunicationPurpose" AS ENUM ('OTP', 'AUTH', 'PASSWORD_RESET', 'TRANSACTIONAL', 'ALERT');

-- CreateEnum
CREATE TYPE "CommunicationHealthStatus" AS ENUM ('UNKNOWN', 'HEALTHY', 'DEGRADED', 'DOWN');

-- CreateEnum
CREATE TYPE "CommunicationCredentialTestStatus" AS ENUM ('NOT_TESTED', 'PASSED', 'FAILED', 'BLOCKED');

-- CreateEnum
CREATE TYPE "OtpTemplatePurpose" AS ENUM ('LOGIN', 'REGISTER', 'PASSWORD_RESET', 'PAYMENT_VERIFY', 'ADMIN_INVITE', 'GENERAL');

-- CreateEnum
CREATE TYPE "OtpTemplateLanguage" AS ENUM ('EN', 'BN');

-- CreateEnum
CREATE TYPE "CommunicationDeliveryStatus" AS ENUM ('QUEUED', 'SENT', 'FAILED', 'RETRIED', 'BLOCKED');

-- CreateTable
CREATE TABLE "communication_providers" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "type" "CommunicationChannel" NOT NULL,
    "status" "CommunicationProviderStatus" NOT NULL DEFAULT 'INACTIVE',
    "environment" "CommunicationProviderEnvironment" NOT NULL DEFAULT 'SANDBOX',
    "is_global" BOOLEAN NOT NULL DEFAULT false,
    "country_code" TEXT,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "supported_purposes" "CommunicationPurpose"[],
    "daily_limit" INTEGER,
    "monthly_limit" INTEGER,
    "rate_limit_per_minute" INTEGER,
    "failure_count" INTEGER NOT NULL DEFAULT 0,
    "success_count" INTEGER NOT NULL DEFAULT 0,
    "last_success_at" TIMESTAMP(3),
    "last_failure_at" TIMESTAMP(3),
    "last_failure_message" TEXT,
    "health_status" "CommunicationHealthStatus" NOT NULL DEFAULT 'UNKNOWN',
    "created_by_id" TEXT,
    "updated_by_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "communication_providers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "communication_provider_credentials" (
    "id" TEXT NOT NULL,
    "provider_id" TEXT NOT NULL,
    "encrypted_secrets" JSONB NOT NULL,
    "masked_secrets_preview" JSONB,
    "api_base_url" TEXT,
    "sender_id" TEXT,
    "from_name" TEXT,
    "from_email" TEXT,
    "smtp_host" TEXT,
    "smtp_port" INTEGER,
    "smtp_secure" BOOLEAN,
    "username_preview" TEXT,
    "last_test_status" "CommunicationCredentialTestStatus" NOT NULL DEFAULT 'NOT_TESTED',
    "last_tested_at" TIMESTAMP(3),
    "last_test_message" TEXT,
    "last_test_details" JSONB,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "communication_provider_credentials_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "communication_routing_rules" (
    "id" TEXT NOT NULL,
    "channel" "CommunicationChannel" NOT NULL,
    "country_code" TEXT,
    "purpose" "CommunicationPurpose" NOT NULL,
    "language" "OtpTemplateLanguage",
    "provider_id" TEXT,
    "fallback_provider_ids" JSONB,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "communication_routing_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "otp_templates" (
    "id" TEXT NOT NULL,
    "channel" "CommunicationChannel" NOT NULL,
    "purpose" "OtpTemplatePurpose" NOT NULL,
    "language" "OtpTemplateLanguage" NOT NULL,
    "subject" TEXT,
    "body" TEXT NOT NULL,
    "variables" JSONB,
    "is_default" BOOLEAN NOT NULL DEFAULT false,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "otp_templates_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "communication_delivery_logs" (
    "id" TEXT NOT NULL,
    "channel" "CommunicationChannel" NOT NULL,
    "purpose" "OtpTemplatePurpose" NOT NULL,
    "recipient" TEXT NOT NULL,
    "country_code" TEXT,
    "provider_id" TEXT,
    "template_id" TEXT,
    "otp_id" TEXT,
    "status" "CommunicationDeliveryStatus" NOT NULL,
    "attempt_no" INTEGER NOT NULL DEFAULT 1,
    "provider_response" JSONB,
    "error_code" TEXT,
    "error_message" TEXT,
    "sent_at" TIMESTAMP(3),
    "failed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "communication_delivery_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "communication_provider_audit_logs" (
    "id" TEXT NOT NULL,
    "actor_admin_id" TEXT,
    "action" TEXT NOT NULL,
    "provider_id" TEXT,
    "metadata" JSONB,
    "ip_address" TEXT,
    "user_agent" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "communication_provider_audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "communication_providers_code_key" ON "communication_providers"("code");

-- CreateIndex
CREATE INDEX "communication_providers_type_status_priority_idx" ON "communication_providers"("type", "status", "priority");

-- CreateIndex
CREATE INDEX "communication_providers_country_code_type_priority_idx" ON "communication_providers"("country_code", "type", "priority");

-- CreateIndex
CREATE INDEX "communication_providers_is_global_type_priority_idx" ON "communication_providers"("is_global", "type", "priority");

-- CreateIndex
CREATE INDEX "communication_providers_deleted_at_idx" ON "communication_providers"("deleted_at");

-- CreateIndex
CREATE INDEX "communication_provider_credentials_provider_id_is_active_idx" ON "communication_provider_credentials"("provider_id", "is_active");

-- CreateIndex
CREATE INDEX "communication_routing_rules_channel_country_code_purpose_pr_idx" ON "communication_routing_rules"("channel", "country_code", "purpose", "priority");

-- CreateIndex
CREATE INDEX "otp_templates_channel_purpose_language_is_active_idx" ON "otp_templates"("channel", "purpose", "language", "is_active");

-- CreateIndex
CREATE UNIQUE INDEX "otp_templates_channel_purpose_language_key" ON "otp_templates"("channel", "purpose", "language");

-- CreateIndex
CREATE INDEX "communication_delivery_logs_channel_purpose_created_at_idx" ON "communication_delivery_logs"("channel", "purpose", "created_at");

-- CreateIndex
CREATE INDEX "communication_delivery_logs_recipient_created_at_idx" ON "communication_delivery_logs"("recipient", "created_at");

-- CreateIndex
CREATE INDEX "communication_delivery_logs_provider_id_created_at_idx" ON "communication_delivery_logs"("provider_id", "created_at");

-- CreateIndex
CREATE INDEX "communication_provider_audit_logs_actor_admin_id_created_at_idx" ON "communication_provider_audit_logs"("actor_admin_id", "created_at");

-- CreateIndex
CREATE INDEX "communication_provider_audit_logs_provider_id_created_at_idx" ON "communication_provider_audit_logs"("provider_id", "created_at");

-- AddForeignKey
ALTER TABLE "communication_providers" ADD CONSTRAINT "communication_providers_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "communication_providers" ADD CONSTRAINT "communication_providers_updated_by_id_fkey" FOREIGN KEY ("updated_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "communication_provider_credentials" ADD CONSTRAINT "communication_provider_credentials_provider_id_fkey" FOREIGN KEY ("provider_id") REFERENCES "communication_providers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "communication_routing_rules" ADD CONSTRAINT "communication_routing_rules_provider_id_fkey" FOREIGN KEY ("provider_id") REFERENCES "communication_providers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "communication_delivery_logs" ADD CONSTRAINT "communication_delivery_logs_provider_id_fkey" FOREIGN KEY ("provider_id") REFERENCES "communication_providers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "communication_delivery_logs" ADD CONSTRAINT "communication_delivery_logs_template_id_fkey" FOREIGN KEY ("template_id") REFERENCES "otp_templates"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "communication_provider_audit_logs" ADD CONSTRAINT "communication_provider_audit_logs_actor_admin_id_fkey" FOREIGN KEY ("actor_admin_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "communication_provider_audit_logs" ADD CONSTRAINT "communication_provider_audit_logs_provider_id_fkey" FOREIGN KEY ("provider_id") REFERENCES "communication_providers"("id") ON DELETE SET NULL ON UPDATE CASCADE;
