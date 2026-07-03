DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_enum e
    JOIN pg_type t ON e.enumtypid = t.oid
    WHERE t.typname = 'AuditAction'
      AND e.enumlabel = 'COMMUNICATION_EVENT_TRIGGERED'
  ) THEN
    ALTER TYPE "AuditAction" ADD VALUE 'COMMUNICATION_EVENT_TRIGGERED';
  END IF;
END $$;

CREATE TABLE "external_communication_events" (
    "id" TEXT NOT NULL,
    "client_id" TEXT NOT NULL,
    "event" TEXT NOT NULL,
    "idempotency_key" TEXT NOT NULL,
    "channels" TEXT[] NOT NULL,
    "recipient_phone" TEXT,
    "recipient_email" TEXT,
    "recipient_name" TEXT,
    "locale" TEXT,
    "payload_json" JSONB NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACCEPTED',
    "result_json" JSONB,
    "request_id" TEXT,
    "source_ip" TEXT,
    "processed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "external_communication_events_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "external_comm_events_client_event_idempotency_key_idx"
  ON "external_communication_events" ("client_id", "event", "idempotency_key");

CREATE INDEX "external_comm_events_client_created_idx"
  ON "external_communication_events" ("client_id", "created_at");

CREATE INDEX "external_comm_events_event_created_idx"
  ON "external_communication_events" ("event", "created_at");

CREATE INDEX "external_comm_events_status_created_idx"
  ON "external_communication_events" ("status", "created_at");

ALTER TABLE "external_communication_events"
  ADD CONSTRAINT "external_communication_events_client_id_fkey"
  FOREIGN KEY ("client_id") REFERENCES "auth_clients"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;
