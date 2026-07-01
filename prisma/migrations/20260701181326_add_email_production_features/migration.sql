-- Add new columns to email_templates (idempotent)
DO $$ BEGIN
  ALTER TABLE "email_templates" ADD COLUMN "locale" TEXT NOT NULL DEFAULT 'en';
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_templates" ADD COLUMN "version" INTEGER NOT NULL DEFAULT 1;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_templates" ADD COLUMN "client_id" TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

-- Update unique constraint on email_templates
DROP INDEX IF EXISTS "email_templates_key_key";
DO $$ BEGIN
  ALTER TABLE "email_templates" ADD CONSTRAINT "email_templates_key_locale_client_id_key" UNIQUE ("key", "locale", "client_id");
EXCEPTION WHEN duplicate_table THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS "email_templates_key_locale_is_active_idx" ON "email_templates"("key", "locale", "is_active");
CREATE INDEX IF NOT EXISTS "email_templates_client_id_is_active_idx" ON "email_templates"("client_id", "is_active");

-- Add foreign key for client_id in email_templates (idempotent)
DO $$ BEGIN
  ALTER TABLE "email_templates" ADD CONSTRAINT "email_templates_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "auth_clients"("id") ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Create email_template_versions table (idempotent)
CREATE TABLE IF NOT EXISTS "email_template_versions" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "template_id" TEXT NOT NULL,
  "version" INTEGER NOT NULL,
  "name" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "preheader" TEXT,
  "html_body" TEXT NOT NULL,
  "text_body" TEXT,
  "variables" JSONB,
  "snapshot" JSONB,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "email_template_versions_template_id_fkey" FOREIGN KEY ("template_id") REFERENCES "email_templates"("id") ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS "email_template_versions_template_id_version_key" ON "email_template_versions"("template_id", "version");
CREATE INDEX IF NOT EXISTS "email_template_versions_template_id_created_at_idx" ON "email_template_versions"("template_id", "created_at");

-- Create client_brandings table (idempotent)
CREATE TABLE IF NOT EXISTS "client_brandings" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "client_id" TEXT NOT NULL UNIQUE,
  "logo_url" TEXT,
  "logo_alt_text" TEXT,
  "brand_color" TEXT,
  "accent_color" TEXT,
  "sender_name" TEXT,
  "sender_email" TEXT,
  "support_email" TEXT,
  "support_phone" TEXT,
  "website_url" TEXT,
  "privacy_url" TEXT,
  "terms_url" TEXT,
  "unsubscribe_url" TEXT,
  "footer_text" TEXT,
  "is_active" BOOLEAN NOT NULL DEFAULT true,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "client_brandings_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "auth_clients"("id") ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS "client_brandings_client_id_idx" ON "client_brandings"("client_id");
CREATE INDEX IF NOT EXISTS "client_brandings_is_active_idx" ON "client_brandings"("is_active");

-- Create email_queues table (idempotent)
CREATE TABLE IF NOT EXISTS "email_queues" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "template_key" TEXT NOT NULL,
  "locale" TEXT NOT NULL DEFAULT 'en',
  "client_id" TEXT,
  "recipient_email" TEXT NOT NULL,
  "recipient_name" TEXT,
  "subject" TEXT NOT NULL,
  "variables" JSONB,
  "status" TEXT NOT NULL DEFAULT 'pending',
  "attempt" INTEGER NOT NULL DEFAULT 0,
  "max_retries" INTEGER NOT NULL DEFAULT 3,
  "next_retry_at" TIMESTAMP(3),
  "last_error" TEXT,
  "send_log_id" TEXT,
  "user_id" TEXT,
  "metadata" JSONB,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "email_queues_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL,
  CONSTRAINT "email_queues_send_log_id_fkey" FOREIGN KEY ("send_log_id") REFERENCES "email_send_logs"("id") ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS "email_queues_status_next_retry_at_idx" ON "email_queues"("status", "next_retry_at");
CREATE INDEX IF NOT EXISTS "email_queues_template_key_status_idx" ON "email_queues"("template_key", "status");
CREATE INDEX IF NOT EXISTS "email_queues_recipient_email_created_at_idx" ON "email_queues"("recipient_email", "created_at");
CREATE INDEX IF NOT EXISTS "email_queues_user_id_status_idx" ON "email_queues"("user_id", "status");

-- Update email_template_audit_logs table (idempotent)
DO $$ BEGIN
  ALTER TABLE "email_template_audit_logs" ADD COLUMN "from_version" INTEGER;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_template_audit_logs" ADD COLUMN "to_version" INTEGER;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

-- Update email_send_logs table
-- Add columns if they don't already exist
DO $$ BEGIN
  ALTER TABLE "email_send_logs" ADD COLUMN "locale" TEXT NOT NULL DEFAULT 'en';
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_send_logs" ADD COLUMN "client_id" TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_send_logs" ADD COLUMN "recipient_name" TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_send_logs" ADD COLUMN "delivery_status" TEXT NOT NULL DEFAULT 'pending';
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_send_logs" ADD COLUMN "attempt_count" INTEGER NOT NULL DEFAULT 1;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_send_logs" ADD COLUMN "sent_at" TIMESTAMP(3);
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_send_logs" ADD COLUMN "failed_at" TIMESTAMP(3);
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

-- Remove queue_id column if it exists (idempotent)
DO $$ BEGIN
  ALTER TABLE "email_send_logs" DROP COLUMN IF EXISTS "queue_id";
EXCEPTION WHEN undefined_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_send_logs" ADD COLUMN "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

-- Create indexes for updated email_send_logs (idempotent)
CREATE INDEX IF NOT EXISTS "email_send_logs_delivery_status_created_at_idx" ON "email_send_logs"("delivery_status", "created_at");
