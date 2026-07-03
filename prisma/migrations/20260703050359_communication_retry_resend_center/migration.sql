-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "CommunicationDeliveryStatus" ADD VALUE 'PENDING';
ALTER TYPE "CommunicationDeliveryStatus" ADD VALUE 'RETRY_SCHEDULED';
ALTER TYPE "CommunicationDeliveryStatus" ADD VALUE 'RETRYING';
ALTER TYPE "CommunicationDeliveryStatus" ADD VALUE 'DEAD_LETTER';
ALTER TYPE "CommunicationDeliveryStatus" ADD VALUE 'CANCELLED';

-- DropForeignKey
ALTER TABLE "email_queues" DROP CONSTRAINT "email_queues_send_log_id_fkey";

-- DropForeignKey
ALTER TABLE "email_queues" DROP CONSTRAINT "email_queues_user_id_fkey";

-- DropForeignKey
ALTER TABLE "email_send_logs" DROP CONSTRAINT "email_send_logs_user_id_fkey";

-- AlterTable
ALTER TABLE "communication_delivery_logs" ADD COLUMN     "cancelled_at" TIMESTAMP(3),
ADD COLUMN     "dead_letter_at" TIMESTAMP(3),
ADD COLUMN     "is_retryable" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "last_error_code" TEXT,
ADD COLUMN     "last_error_message" TEXT,
ADD COLUMN     "last_retry_at" TIMESTAMP(3),
ADD COLUMN     "locked_at" TIMESTAMP(3),
ADD COLUMN     "locked_by" TEXT,
ADD COLUMN     "max_retries" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "next_retry_at" TIMESTAMP(3),
ADD COLUMN     "provider_attempt_chain" JSONB,
ADD COLUMN     "redis_job_id" TEXT,
ADD COLUMN     "resend_payload" JSONB,
ADD COLUMN     "retry_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "retry_policy_key" TEXT;

-- DropTable
DROP TABLE "email_queues";

-- DropTable
DROP TABLE "email_send_logs";

-- CreateIndex
CREATE INDEX "communication_delivery_logs_status_next_retry_at_idx" ON "communication_delivery_logs"("status", "next_retry_at");

-- CreateIndex
CREATE INDEX "communication_delivery_logs_is_retryable_status_created_at__idx" ON "communication_delivery_logs"("is_retryable", "status", "created_at", "id");

