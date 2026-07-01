-- AlterTable
ALTER TABLE "users" ADD COLUMN     "bio" TEXT,
ADD COLUMN     "department" TEXT,
ADD COLUMN     "interface_preferences" JSONB,
ADD COLUMN     "job_title" TEXT,
ADD COLUMN     "last_login_at" TIMESTAMP(3),
ADD COLUMN     "last_password_changed_at" TIMESTAMP(3),
ADD COLUMN     "notification_preferences" JSONB,
ADD COLUMN     "organization" TEXT;
