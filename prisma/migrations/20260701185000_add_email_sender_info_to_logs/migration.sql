-- Add sender information columns to email_send_logs for tracking which sender was used
ALTER TABLE "email_send_logs" ADD COLUMN "sender_name" TEXT;
ALTER TABLE "email_send_logs" ADD COLUMN "sender_email" TEXT;

-- Add index for filtering by client_id on email_send_logs
CREATE INDEX "email_send_logs_client_id_created_at_idx" ON "email_send_logs"("client_id", "created_at");
