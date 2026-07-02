-- Phase 2.6A (docs/phase-2-6a-app-aware-communication-routing-ui.md):
-- app-aware communication routing rules + reply-to branding fields.
-- All changes are additive/nullable-with-defaults — no data loss risk,
-- existing rows (all with appId=null) keep working unchanged as system
-- defaults.

ALTER TABLE "communication_routing_rules" ADD COLUMN "app_id" TEXT;
ALTER TABLE "communication_routing_rules" ADD COLUMN "enabled" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "communication_routing_rules" ADD COLUMN "fallback_enabled" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "communication_routing_rules" ADD COLUMN "environment" "CommunicationProviderEnvironment";

CREATE INDEX "communication_routing_rules_app_id_channel_country_code_pu_idx"
  ON "communication_routing_rules" ("app_id", "channel", "country_code", "purpose", "priority");

ALTER TABLE "communication_routing_rules"
  ADD CONSTRAINT "communication_routing_rules_app_id_fkey"
  FOREIGN KEY ("app_id") REFERENCES "auth_clients"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "email_branding_settings" ADD COLUMN "reply_to" TEXT;
ALTER TABLE "client_brandings" ADD COLUMN "reply_to" TEXT;
