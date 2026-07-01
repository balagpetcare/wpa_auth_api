-- CreateEnum
CREATE TYPE "AdminNotificationSeverity" AS ENUM ('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'SECURITY');

-- CreateEnum
CREATE TYPE "AdminNotificationCategory" AS ENUM ('SYSTEM', 'SECURITY', 'USER_MANAGEMENT', 'AUTH', 'SETTINGS', 'BILLING', 'INTEGRATION');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'USER_STATUS_CHANGED';
ALTER TYPE "AuditAction" ADD VALUE 'USER_PASSWORD_RESET_TRIGGERED';
ALTER TYPE "AuditAction" ADD VALUE 'USER_ACCOUNT_DELETED';
ALTER TYPE "AuditAction" ADD VALUE 'USER_SESSIONS_REVOKED';
ALTER TYPE "AuditAction" ADD VALUE 'USER_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'PROFILE_AVATAR_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'PROFILE_AVATAR_REMOVED';

-- CreateTable
CREATE TABLE "admin_notifications" (
    "id" TEXT NOT NULL,
    "user_id" TEXT,
    "type" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "severity" "AdminNotificationSeverity" NOT NULL,
    "category" "AdminNotificationCategory" NOT NULL,
    "action_url" TEXT,
    "metadata" JSONB,
    "read_at" TIMESTAMP(3),
    "dismissed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "admin_notifications_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "admin_notifications_user_id_read_at_created_at_idx" ON "admin_notifications"("user_id", "read_at", "created_at");

-- CreateIndex
CREATE INDEX "admin_notifications_created_at_idx" ON "admin_notifications"("created_at");

-- CreateIndex
CREATE INDEX "admin_notifications_severity_idx" ON "admin_notifications"("severity");

-- CreateIndex
CREATE INDEX "admin_notifications_category_idx" ON "admin_notifications"("category");

-- CreateIndex
CREATE INDEX "admin_notifications_dismissed_at_idx" ON "admin_notifications"("dismissed_at");

-- AddForeignKey
ALTER TABLE "admin_notifications" ADD CONSTRAINT "admin_notifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
