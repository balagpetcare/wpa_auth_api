# Phase 3.3 Queue/Worker Extraction for Email, SMS, and Notifications

Date: 2026-07-02

## 1. Files Changed

- `package.json`
- `src/lib/antiAbuse.ts`
- `src/lib/communicationQueue.ts`
- `src/lib/sendTemplatedEmail.ts`
- `src/modules/communication/communication.service.ts`
- `src/server.ts`
- `src/workers/communication.worker.ts`
- `docs/phase-3-3-queue-worker-communication.md`

## 2. Queue Design

Implemented a Redis-backed queue using the existing Redis dependency.

Key points:
- jobs are pushed to a Redis list
- a Redis-backed worker process consumes jobs independently from the API process
- job payloads do not contain SMTP/SMS credentials
- job deduplication uses a Redis key derived from a hash of the payload
- a processing list and dead-letter list are used to reduce duplicate execution risk and preserve failures for inspection

Queue storage keys:
- `queue:communication`
- `queue:communication:processing`
- `queue:communication:dlq`
- `queue:communication:dedupe:*`

## 3. Worker Entrypoint

Added:
- `src/workers/communication.worker.ts`

Worker responsibilities:
- consume queued email jobs
- consume queued SMS jobs
- create queued admin notifications
- acknowledge successful jobs
- move failed jobs to the dead-letter list
- load provider credentials server-side at send time

## 4. Job Payload Structure

Supported queue jobs:
- `send_email`
- `send_sms`
- `send_admin_notification`
- `communication_retry`
- `provider_health_check`

Payload rules:
- no SMTP/SMS credentials are stored in job payloads
- email jobs carry the rendered subject/text/html plus recipient metadata
- SMS jobs carry the destination, message body, and purpose
- admin notification jobs carry the notification content only

## 5. Idempotency / Retry / Dead-Letter Behavior

Implemented:
- dedupe key based on a SHA-256 hash of the normalized job payload
- Redis `NX` key to prevent duplicate enqueue of the same payload during the TTL window
- processing list to keep in-flight jobs visible during worker execution
- dead-letter list for failed jobs
- worker-side acknowledgement on success

Behavioral notes:
- provider credentials are resolved in the worker, not in the API request path
- retry orchestration for failed jobs is present at the worker layer, but a fully sophisticated per-job exponential retry scheduler is still a future enhancement

## 6. Verification Results

Passed in this session:
- `npx prisma validate`
- `npx tsc --noEmit`
- `npm run build`

Not fully executed in this session:
- full live API + worker send test
- provider failure simulation
- repeated worker restart duplicate-send test

Reason:
- the code was compiled and wired successfully, but the live Redis/provider integration check should be exercised in the target runtime environment where SMTP/SMS providers and Redis are fully configured

## 7. PM2 / Deployment Notes

Added worker script:
- `npm run worker:communication`

Suggested process layout:
- `api`: `npm run dev` or `npm start`
- `communication-worker`: `npm run worker:communication`

PM2 example:

```bash
pm2 start npm --name wpa-auth-api -- run start
pm2 start npm --name wpa-auth-worker -- run worker:communication
```

Deployment note:
- run the API and worker as separate processes so communication throughput scales horizontally without blocking request handling

## 8. Remaining Queue Gaps

- the current queue is Redis-list based rather than a full managed queue framework
- no browser-facing job status UI was added in this phase
- provider-failure retry scheduling can be expanded further
- SMS-specific end-to-end worker verification still needs a live provider test
- a richer dead-letter replay tool can be added in a later phase
