-- Add first-class account/data deletion workflow.

CREATE TYPE "DeletionRequestType" AS ENUM ('ACCOUNT', 'DATA');
CREATE TYPE "DeletionRequestStatus" AS ENUM ('PENDING_REVIEW', 'SCHEDULED', 'PROCESSING', 'COMPLETED', 'CANCELLED', 'REJECTED', 'FAILED');
CREATE TYPE "DeletionRequestSource" AS ENUM ('AUTHENTICATED_WEB', 'PUBLIC_WEB', 'EMAIL_REQUEST', 'META_CALLBACK', 'ADMIN');
CREATE TYPE "DeletionRequestEventType" AS ENUM ('REQUEST_CREATED', 'STATUS_CHANGED', 'APPROVED', 'REJECTED', 'CANCELLED', 'PROCESSING_STARTED', 'PROCESSING_COMPLETED', 'PROCESSING_FAILED', 'ANONYMIZED', 'SOCIAL_IDENTITY_DISCONNECTED', 'SESSION_REVOKED');

ALTER TYPE "AuditAction" ADD VALUE 'ACCOUNT_DELETION_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCOUNT_DELETION_CANCELLED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCOUNT_DELETION_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCOUNT_DELETION_REJECTED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCOUNT_DELETION_PROCESSING_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCOUNT_DELETION_PROCESSING_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'ACCOUNT_DELETION_PROCESSING_FAILED';
ALTER TYPE "AuditAction" ADD VALUE 'DATA_DELETION_REQUESTED';
ALTER TYPE "AuditAction" ADD VALUE 'DATA_DELETION_CANCELLED';
ALTER TYPE "AuditAction" ADD VALUE 'DATA_DELETION_APPROVED';
ALTER TYPE "AuditAction" ADD VALUE 'DATA_DELETION_REJECTED';
ALTER TYPE "AuditAction" ADD VALUE 'DATA_DELETION_PROCESSING_STARTED';
ALTER TYPE "AuditAction" ADD VALUE 'DATA_DELETION_PROCESSING_COMPLETED';
ALTER TYPE "AuditAction" ADD VALUE 'DATA_DELETION_PROCESSING_FAILED';

CREATE TABLE "deletion_requests" (
    "id" TEXT NOT NULL,
    "confirmation_code" TEXT NOT NULL,
    "request_type" "DeletionRequestType" NOT NULL,
    "status" "DeletionRequestStatus" NOT NULL DEFAULT 'PENDING_REVIEW',
    "provider" "OAuthProvider",
    "request_source" "DeletionRequestSource" NOT NULL,
    "user_id" TEXT,
    "email_hash" TEXT,
    "email_reference" TEXT,
    "requested_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "grace_period_deadline_at" TIMESTAMP(3),
    "processed_at" TIMESTAMP(3),
    "cancelled_at" TIMESTAMP(3),
    "cancelled_by_user_id" TEXT,
    "cancelled_by_admin_id" TEXT,
    "reviewed_at" TIMESTAMP(3),
    "reviewed_by_admin_id" TEXT,
    "failure_reason" TEXT,
    "audit_metadata" JSONB,
    "source_ip" TEXT,
    "source_user_agent" TEXT,
    "meta_payload" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "deletion_requests_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "deletion_requests_confirmation_code_key" ON "deletion_requests"("confirmation_code");
CREATE INDEX "deletion_requests_status_requested_at_idx" ON "deletion_requests"("status", "requested_at");
CREATE INDEX "deletion_requests_request_type_status_requested_at_idx" ON "deletion_requests"("request_type", "status", "requested_at");
CREATE INDEX "deletion_requests_provider_requested_at_idx" ON "deletion_requests"("provider", "requested_at");
CREATE INDEX "deletion_requests_user_id_requested_at_idx" ON "deletion_requests"("user_id", "requested_at");

ALTER TABLE "deletion_requests"
  ADD CONSTRAINT "deletion_requests_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

CREATE TABLE "deletion_request_events" (
    "id" TEXT NOT NULL,
    "deletion_request_id" TEXT NOT NULL,
    "event_type" "DeletionRequestEventType" NOT NULL,
    "actor_source" TEXT NOT NULL DEFAULT 'SYSTEM',
    "actor_user_id" TEXT,
    "actor_admin_id" TEXT,
    "metadata" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "deletion_request_events_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "deletion_request_events_request_created_at_idx" ON "deletion_request_events"("deletion_request_id", "created_at");
CREATE INDEX "deletion_request_events_event_type_created_at_idx" ON "deletion_request_events"("event_type", "created_at");

ALTER TABLE "deletion_request_events"
  ADD CONSTRAINT "deletion_request_events_deletion_request_id_fkey"
  FOREIGN KEY ("deletion_request_id") REFERENCES "deletion_requests"("id") ON DELETE CASCADE ON UPDATE CASCADE;
