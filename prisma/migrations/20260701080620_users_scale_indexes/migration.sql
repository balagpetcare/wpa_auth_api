-- CreateIndex
CREATE INDEX "oauth_accounts_provider_idx" ON "oauth_accounts"("provider");

-- CreateIndex
CREATE INDEX "users_created_at_idx" ON "users"("created_at");

-- CreateIndex
CREATE INDEX "users_last_login_at_idx" ON "users"("last_login_at");

-- CreateIndex
CREATE INDEX "users_created_at_id_idx" ON "users"("created_at", "id");

-- CreateIndex
CREATE INDEX "users_last_login_at_id_idx" ON "users"("last_login_at", "id");

-- CreateIndex
CREATE INDEX "users_status_created_at_id_idx" ON "users"("status", "created_at", "id");
