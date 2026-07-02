CREATE INDEX IF NOT EXISTS "audit_logs_created_at_id_idx" ON "audit_logs" ("created_at", "id");
CREATE INDEX IF NOT EXISTS "audit_logs_user_id_created_at_id_idx" ON "audit_logs" ("user_id", "created_at", "id");

CREATE INDEX IF NOT EXISTS "security_events_created_at_id_idx" ON "security_events" ("created_at", "id");
CREATE INDEX IF NOT EXISTS "security_events_user_id_created_at_id_idx" ON "security_events" ("user_id", "created_at", "id");
CREATE INDEX IF NOT EXISTS "security_events_type_created_at_id_idx" ON "security_events" ("type", "created_at", "id");

CREATE INDEX IF NOT EXISTS "admin_notifications_user_id_created_at_id_idx" ON "admin_notifications" ("user_id", "created_at", "id");

CREATE INDEX IF NOT EXISTS "login_sessions_user_id_created_at_id_idx" ON "login_sessions" ("user_id", "created_at", "id");
CREATE INDEX IF NOT EXISTS "login_sessions_client_id_created_at_id_idx" ON "login_sessions" ("client_id", "created_at", "id");

CREATE INDEX IF NOT EXISTS "communication_delivery_logs_created_at_id_idx" ON "communication_delivery_logs" ("created_at", "id");
CREATE INDEX IF NOT EXISTS "communication_delivery_logs_channel_created_at_id_idx" ON "communication_delivery_logs" ("channel", "created_at", "id");
CREATE INDEX IF NOT EXISTS "communication_delivery_logs_provider_id_created_at_id_idx" ON "communication_delivery_logs" ("provider_id", "created_at", "id");
CREATE INDEX IF NOT EXISTS "communication_delivery_logs_status_created_at_id_idx" ON "communication_delivery_logs" ("status", "created_at", "id");

CREATE INDEX IF NOT EXISTS "communication_provider_audit_logs_created_at_id_idx" ON "communication_provider_audit_logs" ("created_at", "id");
CREATE INDEX IF NOT EXISTS "communication_provider_audit_logs_provider_id_created_at_id_idx" ON "communication_provider_audit_logs" ("provider_id", "created_at", "id");
CREATE INDEX IF NOT EXISTS "comm_provider_audit_actor_created_idx" ON "communication_provider_audit_logs" ("actor_admin_id", "created_at", "id");

CREATE INDEX IF NOT EXISTS "email_send_logs_created_at_id_idx" ON "email_send_logs" ("created_at", "id");
CREATE INDEX IF NOT EXISTS "email_send_logs_template_key_created_at_id_idx" ON "email_send_logs" ("template_key", "created_at", "id");
CREATE INDEX IF NOT EXISTS "email_send_logs_status_created_at_id_idx" ON "email_send_logs" ("status", "created_at", "id");
CREATE INDEX IF NOT EXISTS "email_send_logs_client_id_created_at_id_idx" ON "email_send_logs" ("client_id", "created_at", "id");
