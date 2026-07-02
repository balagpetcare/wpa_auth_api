import { logger } from '../lib/logger.js';
import { closeRedisClient, createRedisClient } from '../lib/redis.js';
import { prisma } from '../lib/db.js';
import { createAdminNotification } from '../lib/adminNotifications.js';
import { reserveNextCommunicationJob, acknowledgeCommunicationJob, moveCommunicationJobToDlq } from '../lib/communicationQueue.js';
import { deliverQueuedEmail, deliverQueuedSms } from '../modules/communication/communication.service.js';
import type { Prisma } from '@prisma/client';

let running = true;

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
        await createAdminNotification({
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
      case 'provider_health_check':
        logger.info({ jobType: job.type, payload: job.payload }, 'Communication maintenance job received');
        break;
      default:
        logger.warn({ job }, 'Unknown communication job type');
    }

    await acknowledgeCommunicationJob(job);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMessage, jobType: job.type, jobId: job.id }, 'Communication job failed');
    await moveCommunicationJobToDlq(job, errorMessage);
  }
}

async function loop() {
  logger.info('Communication worker started');
  while (running) {
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
