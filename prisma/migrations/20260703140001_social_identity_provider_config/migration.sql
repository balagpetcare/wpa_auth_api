-- AlterEnum
ALTER TYPE "OAuthProvider" ADD VALUE 'MICROSOFT';
ALTER TYPE "OAuthProvider" ADD VALUE 'LINKEDIN';
ALTER TYPE "OAuthProvider" ADD VALUE 'TIKTOK';
ALTER TYPE "OAuthProvider" ADD VALUE 'X';
ALTER TYPE "OAuthProvider" ADD VALUE 'GITHUB';

-- CreateEnum
CREATE TYPE "SocialIdentityProviderStatus" AS ENUM ('ACTIVE', 'INACTIVE');
CREATE TYPE "SocialIdentityProviderEnvironment" AS ENUM ('SANDBOX', 'LIVE');
CREATE TYPE "SocialIdentityProviderPlacement" AS ENUM ('MAIN', 'MORE', 'HIDDEN');

-- CreateTable
CREATE TABLE "social_identity_provider_configs" (
    "id" TEXT NOT NULL,
    "provider" "OAuthProvider" NOT NULL,
    "display_name" TEXT NOT NULL,
    "client_id" TEXT,
    "client_secret_encrypted" TEXT,
    "authorization_url" TEXT NOT NULL,
    "token_url" TEXT NOT NULL,
    "user_info_url" TEXT,
    "scopes" TEXT[] NOT NULL,
    "redirect_uri" TEXT NOT NULL,
    "status" "SocialIdentityProviderStatus" NOT NULL DEFAULT 'INACTIVE',
    "environment" "SocialIdentityProviderEnvironment" NOT NULL DEFAULT 'LIVE',
    "placement" "SocialIdentityProviderPlacement" NOT NULL DEFAULT 'MAIN',
    "sort_order" INTEGER NOT NULL DEFAULT 0,
    "show_on_login" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "created_by_admin_id" TEXT,
    "updated_by_admin_id" TEXT,

    CONSTRAINT "social_identity_provider_configs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "social_identity_provider_configs_provider_key" ON "social_identity_provider_configs"("provider");
CREATE INDEX "social_identity_provider_configs_status_show_on_login_place_idx" ON "social_identity_provider_configs"("status", "show_on_login", "placement", "sort_order");

-- AddForeignKey
ALTER TABLE "social_identity_provider_configs" ADD CONSTRAINT "social_identity_provider_configs_created_by_admin_id_fkey" FOREIGN KEY ("created_by_admin_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "social_identity_provider_configs" ADD CONSTRAINT "social_identity_provider_configs_updated_by_admin_id_fkey" FOREIGN KEY ("updated_by_admin_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
