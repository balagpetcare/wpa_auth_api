-- Create the email domain tables that later migrations expect to exist.
-- These are additive and idempotent so the migration replays cleanly in a shadow database.

CREATE TABLE IF NOT EXISTS "email_templates" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "preheader" TEXT,
    "html_body" TEXT NOT NULL,
    "text_body" TEXT,
    "variables" JSONB,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "updated_by_admin_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "locale" TEXT NOT NULL DEFAULT 'en',
    "version" INTEGER NOT NULL DEFAULT 1,
    "client_id" TEXT,

    CONSTRAINT "email_templates_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "email_templates_key_locale_is_active_idx" ON "email_templates"("key", "locale", "is_active");
CREATE INDEX IF NOT EXISTS "email_templates_client_id_is_active_idx" ON "email_templates"("client_id", "is_active");
CREATE INDEX IF NOT EXISTS "email_templates_key_is_active_idx" ON "email_templates"("key", "is_active");

DROP INDEX IF EXISTS "email_templates_key_locale_client_id_key";
DO $$ BEGIN
  ALTER TABLE "email_templates" ADD CONSTRAINT "email_templates_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "auth_clients"("id") ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_templates" ADD CONSTRAINT "email_templates_updated_by_admin_id_fkey" FOREIGN KEY ("updated_by_admin_id") REFERENCES "users"("id") ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS "email_template_versions" (
    "id" TEXT NOT NULL,
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

    CONSTRAINT "email_template_versions_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "email_template_versions_template_id_version_key" ON "email_template_versions"("template_id", "version");
CREATE INDEX IF NOT EXISTS "email_template_versions_template_id_created_at_idx" ON "email_template_versions"("template_id", "created_at");

DO $$ BEGIN
  ALTER TABLE "email_template_versions" ADD CONSTRAINT "email_template_versions_template_id_fkey" FOREIGN KEY ("template_id") REFERENCES "email_templates"("id") ON DELETE CASCADE ON UPDATE NO ACTION;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS "email_template_audit_logs" (
    "id" TEXT NOT NULL,
    "template_id" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "changed_fields" JSONB,
    "actor_admin_id" TEXT,
    "ip_address" TEXT,
    "user_agent" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "from_version" INTEGER,
    "to_version" INTEGER,

    CONSTRAINT "email_template_audit_logs_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "email_template_audit_logs_template_id_created_at_idx" ON "email_template_audit_logs"("template_id", "created_at");
CREATE INDEX IF NOT EXISTS "email_template_audit_logs_actor_admin_id_created_at_idx" ON "email_template_audit_logs"("actor_admin_id", "created_at");

DO $$ BEGIN
  ALTER TABLE "email_template_audit_logs" ADD CONSTRAINT "email_template_audit_logs_actor_admin_id_fkey" FOREIGN KEY ("actor_admin_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_template_audit_logs" ADD CONSTRAINT "email_template_audit_logs_template_id_fkey" FOREIGN KEY ("template_id") REFERENCES "email_templates"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS "email_branding_settings" (
    "id" TEXT NOT NULL,
    "logo_url" TEXT,
    "logo_alt_text" TEXT,
    "primary_color" TEXT,
    "text_color" TEXT,
    "header_background_color" TEXT,
    "footer_background_color" TEXT,
    "support_email" TEXT,
    "support_phone" TEXT,
    "website_url" TEXT,
    "privacy_url" TEXT,
    "terms_url" TEXT,
    "help_url" TEXT,
    "contact_url" TEXT,
    "facebook_url" TEXT,
    "instagram_url" TEXT,
    "linkedin_url" TEXT,
    "twitter_url" TEXT,
    "youtube_url" TEXT,
    "tiktok_url" TEXT,
    "footer_text" TEXT,
    "address" TEXT,
    "legal_disclaimer" TEXT,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "updated_by_admin_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "brand_name" TEXT NOT NULL,

    CONSTRAINT "email_branding_settings_pkey" PRIMARY KEY ("id")
);

DO $$ BEGIN
  ALTER TABLE "email_branding_settings" ADD CONSTRAINT "email_branding_settings_updated_by_admin_id_fkey" FOREIGN KEY ("updated_by_admin_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS "client_brandings" (
    "id" TEXT NOT NULL,
    "client_id" TEXT NOT NULL,
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
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "client_brandings_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "client_brandings_client_id_key" ON "client_brandings"("client_id");
CREATE INDEX IF NOT EXISTS "client_brandings_client_id_idx" ON "client_brandings"("client_id");
CREATE INDEX IF NOT EXISTS "client_brandings_is_active_idx" ON "client_brandings"("is_active");

DO $$ BEGIN
  ALTER TABLE "client_brandings" ADD CONSTRAINT "client_brandings_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "auth_clients"("id") ON DELETE CASCADE ON UPDATE NO ACTION;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS "email_send_logs" (
    "id" TEXT NOT NULL,
    "template_key" TEXT NOT NULL,
    "recipient_email" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "variables" JSONB,
    "status" TEXT NOT NULL,
    "user_id" TEXT,
    "error_message" TEXT,
    "provider_response" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "locale" TEXT NOT NULL DEFAULT 'en',
    "client_id" TEXT,
    "recipient_name" TEXT,
    "delivery_status" TEXT NOT NULL DEFAULT 'pending',
    "attempt_count" INTEGER NOT NULL DEFAULT 1,
    "sent_at" TIMESTAMP(3),
    "failed_at" TIMESTAMP(3),
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "email_send_logs_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "email_send_logs_template_key_created_at_idx" ON "email_send_logs"("template_key", "created_at");
CREATE INDEX IF NOT EXISTS "email_send_logs_recipient_email_created_at_idx" ON "email_send_logs"("recipient_email", "created_at");
CREATE INDEX IF NOT EXISTS "email_send_logs_user_id_created_at_idx" ON "email_send_logs"("user_id", "created_at");
CREATE INDEX IF NOT EXISTS "email_send_logs_status_created_at_idx" ON "email_send_logs"("status", "created_at");
CREATE INDEX IF NOT EXISTS "email_send_logs_delivery_status_created_at_idx" ON "email_send_logs"("delivery_status", "created_at");

DO $$ BEGIN
  ALTER TABLE "email_send_logs" ADD CONSTRAINT "email_send_logs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS "email_queues" (
    "id" TEXT NOT NULL,
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
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "email_queues_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "email_queues_status_next_retry_at_idx" ON "email_queues"("status", "next_retry_at");
CREATE INDEX IF NOT EXISTS "email_queues_template_key_status_idx" ON "email_queues"("template_key", "status");
CREATE INDEX IF NOT EXISTS "email_queues_recipient_email_created_at_idx" ON "email_queues"("recipient_email", "created_at");
CREATE INDEX IF NOT EXISTS "email_queues_user_id_status_idx" ON "email_queues"("user_id", "status");

DO $$ BEGIN
  ALTER TABLE "email_queues" ADD CONSTRAINT "email_queues_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE NO ACTION;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_queues" ADD CONSTRAINT "email_queues_send_log_id_fkey" FOREIGN KEY ("send_log_id") REFERENCES "email_send_logs"("id") ON DELETE SET NULL ON UPDATE NO ACTION;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Add new columns to email_templates if the table was created earlier in the replay chain or already exists.
DO $$ BEGIN
  ALTER TABLE "email_templates" ADD COLUMN "locale" TEXT NOT NULL DEFAULT 'en';
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_templates" ADD COLUMN "version" INTEGER NOT NULL DEFAULT 1;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_templates" ADD COLUMN "client_id" TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

-- Align unique and foreign key constraints with the current schema.
DROP INDEX IF EXISTS "email_templates_key_key";
DO $$ BEGIN
  ALTER TABLE "email_templates" ADD CONSTRAINT "email_templates_key_locale_client_id_key" UNIQUE ("key", "locale", "client_id");
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS "email_templates_key_locale_is_active_idx" ON "email_templates"("key", "locale", "is_active");
CREATE INDEX IF NOT EXISTS "email_templates_client_id_is_active_idx" ON "email_templates"("client_id", "is_active");

-- Update email_send_logs columns to match the current Prisma schema.
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

DO $$ BEGIN
  ALTER TABLE "email_send_logs" DROP COLUMN IF EXISTS "queue_id";
EXCEPTION WHEN undefined_column THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "email_send_logs" ADD COLUMN "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS "email_send_logs_delivery_status_created_at_idx" ON "email_send_logs"("delivery_status", "created_at");
