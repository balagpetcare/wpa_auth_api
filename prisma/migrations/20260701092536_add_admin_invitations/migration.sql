-- CreateEnum
CREATE TYPE "InvitationStatus" AS ENUM ('PENDING', 'ACCEPTED', 'EXPIRED', 'REVOKED');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_INVITATION_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_INVITATION_RESENT';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_INVITATION_REVOKED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_INVITATION_ACCEPTED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_ROLE_ASSIGNED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_ROLE_REMOVED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_ACCESS_GRANTED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_ACCESS_REMOVED';

-- CreateTable
CREATE TABLE "admin_invitations" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "invited_by_user_id" TEXT NOT NULL,
    "invited_user_id" TEXT,
    "token_hash" TEXT NOT NULL,
    "status" "InvitationStatus" NOT NULL DEFAULT 'PENDING',
    "message" TEXT,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "accepted_at" TIMESTAMP(3),
    "revoked_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "admin_invitations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "admin_invitation_roles" (
    "invitation_id" TEXT NOT NULL,
    "role_id" TEXT NOT NULL,

    CONSTRAINT "admin_invitation_roles_pkey" PRIMARY KEY ("invitation_id","role_id")
);

-- CreateIndex
CREATE UNIQUE INDEX "admin_invitations_token_hash_key" ON "admin_invitations"("token_hash");

-- CreateIndex
CREATE INDEX "admin_invitations_email_idx" ON "admin_invitations"("email");

-- CreateIndex
CREATE INDEX "admin_invitations_status_idx" ON "admin_invitations"("status");

-- CreateIndex
CREATE INDEX "admin_invitations_expires_at_idx" ON "admin_invitations"("expires_at");

-- CreateIndex
CREATE INDEX "admin_invitations_invited_by_user_id_idx" ON "admin_invitations"("invited_by_user_id");

-- CreateIndex
CREATE INDEX "admin_invitations_token_hash_idx" ON "admin_invitations"("token_hash");

-- CreateIndex
CREATE INDEX "admin_invitation_roles_invitation_id_idx" ON "admin_invitation_roles"("invitation_id");

-- CreateIndex
CREATE INDEX "admin_invitation_roles_role_id_idx" ON "admin_invitation_roles"("role_id");

-- AddForeignKey
ALTER TABLE "admin_invitation_roles" ADD CONSTRAINT "admin_invitation_roles_invitation_id_fkey" FOREIGN KEY ("invitation_id") REFERENCES "admin_invitations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "admin_invitation_roles" ADD CONSTRAINT "admin_invitation_roles_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE CASCADE ON UPDATE CASCADE;
