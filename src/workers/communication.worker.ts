import { logger } from '../lib/logger.js';
import { closeRedisClient, createRedisClient } from '../lib/redis.js';
import { prisma } from '../lib/db.js';
import { createAdminNotificationRecord } from '../lib/adminNotifications.js';
import { incrementMetric } from '../lib/metrics.js';
import '../config/index.js';
import {
  reserveNextCommunicationJob,
  acknowledgeCommunicationJob,
  moveCommunicationJobToDlq,
  scheduleCommunicationRetry,
  promoteDueCommunicationJobs,
  recoverStalledCommunicationJobs,
} from '../lib/communicationQueue.js';
import { deliverQueuedEmail, deliverQueuedSms, processDueRetries, executeRetry } from '../modules/communication/communication.service.js';
import { config } from '../config/index.js';
import type { Prisma } from '@prisma/client';

let running = true;
const RETRY_SCAN_INTERVAL_MS = 15_000;
let lastRetryScanAt = 0;

async function touchHeartbeat() {
  const redis = createRedisClient();
  if (!redis) return;
  try {
    await redis.set('worker:communication:heartbeat', new Date().toISOString(), 'EX', 120);
  } catch {
    // Best-effort heartbeat only.
  }
}

async function handleJob(job: Awaited<ReturnType<typeof reserveNextCommunicationJob>> extends infer T ? T : never) {
  if (!job) return;
  try {
    switch (job.type) {
      case 'send_email':
        await deliverQueuedEmail({
          to: job.payload.recipientEmail,
          subject: job.payload.subject,
          text: job.payload.text,
          html: job.payload.html,
          purpose: (job.payload.purpose as any) ?? 'GENERAL',
          clientId: job.payload.clientId ?? null,
          senderName: job.payload.recipientName ?? null,
          senderEmail: null,
          templateKey: job.payload.templateKey ?? null,
        });
        break;
      case 'send_sms':
        await deliverQueuedSms({
          to: job.payload.to,
          message: job.payload.message,
          purpose: job.payload.purpose as any,
          clientId: job.payload.clientId ?? null,
        });
        break;
      case 'send_admin_notification':
        await createAdminNotificationRecord({
          type: job.payload.type,
          title: job.payload.title,
          message: job.payload.message,
          severity: job.payload.severity as any,
          category: job.payload.category as any,
          actionUrl: job.payload.actionUrl ?? undefined,
          metadata: job.payload.metadata as Prisma.InputJsonValue | undefined,
        });
        break;
      case 'communication_retry':
        // On-demand nudge to retry a single CommunicationDeliveryLog row
        // (payload.sourceId is the delivery log id). The periodic scan in
        // loop() below is the primary path for RETRY_SCHEDULED rows; this
        // job type exists for callers that want to force an immediate
        // retry attempt without waiting for the next scan tick.
        await executeRetry(job.payload.sourceId);
        break;
      case 'provider_health_check':
        logger.info({ jobType: job.type, payload: job.payload }, 'Communication maintenance job received');
        break;
      default:
        logger.warn({ job }, 'Unknown communication job type');
    }

    await acknowledgeCommunicationJob(job);
    incrementMetric('worker_processed_total');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMessage, jobType: job.type, jobId: job.id }, 'Communication job failed');
    incrementMetric('worker_failure_total');
    if (job.attempts + 1 < job.maxAttempts) {
      const backoffMs = Math.min(60_000 * Math.pow(2, job.attempts), 24 * 60 * 60 * 1000);
      await scheduleCommunicationRetry(job, backoffMs, errorMessage);
    } else {
      await moveCommunicationJobToDlq(job, errorMessage);
      incrementMetric('worker_dlq_total');
    }
  }
}

async function scanDueRetriesIfEnabled() {
  if (!config.COMMUNICATION_RETRY_WORKER_ENABLED) return;
  if (Date.now() - lastRetryScanAt < RETRY_SCAN_INTERVAL_MS) return;
  lastRetryScanAt = Date.now();
  try {
    const { processed } = await processDueRetries();
    if (processed > 0) {
      logger.info({ processed }, 'Communication retry worker processed due retries');
    }
  } catch (error) {
    logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Communication retry scan failed');
  }
}

async function loop() {
  logger.info({ retryWorkerEnabled: config.COMMUNICATION_RETRY_WORKER_ENABLED }, 'Communication worker started');
  while (running) {
    await touchHeartbeat();
    await promoteDueCommunicationJobs();
    await recoverStalledCommunicationJobs();
    await scanDueRetriesIfEnabled();
    const job = await reserveNextCommunicationJob(5);
    if (!job) continue;
    await handleJob(job as any);
  }
}

async function shutdown() {
  running = false;
  logger.info('Communication worker stopping');
  await closeRedisClient();
  await prisma.$disconnect();
}

createRedisClient();
loop().catch((error) => {
  logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Communication worker crashed');
  process.exit(1);
});

process.on('SIGINT', () => {
  void shutdown().finally(() => process.exit(0));
});
process.on('SIGTERM', () => {
  void shutdown().finally(() => process.exit(0));
});
