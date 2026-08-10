-- Additive only: hand-authored (not via `prisma migrate dev`) because the
-- dev database has pre-existing, unrelated schema drift (admin_notifications,
-- client_brandings, communication_routing_rules, email_templates) that would
-- otherwise require a destructive `prisma migrate reset`. This migration
-- touches only the `users` table (three new nullable columns) and adds one
-- new table, so it is safe to apply directly regardless of that drift.

-- AlterTable
ALTER TABLE "users" ADD COLUMN "first_name" TEXT;
ALTER TABLE "users" ADD COLUMN "last_name" TEXT;
ALTER TABLE "users" ADD COLUMN "date_of_birth" DATE;

-- CreateTable
CREATE TABLE "phone_change_tokens" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "phone" TEXT NOT NULL,
    "code_hash" TEXT NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "used_at" TIMESTAMP(3),
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "phone_change_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "phone_change_tokens_user_id_idx" ON "phone_change_tokens"("user_id");

-- CreateIndex
CREATE INDEX "phone_change_tokens_expires_at_idx" ON "phone_change_tokens"("expires_at");

-- AddForeignKey
ALTER TABLE "phone_change_tokens" ADD CONSTRAINT "phone_change_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
