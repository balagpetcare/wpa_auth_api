import { config } from '../config/index.js';
import { logger } from '../lib/logger.js';
import { closeRedisClient, createRedisClient } from '../lib/redis.js';
import { prisma } from '../lib/db.js';
import { processDueDeletionRequests } from '../modules/deletion/deletion.service.js';

let running = true;

async function touchHeartbeat() {
  const redis = createRedisClient();
  if (!redis) return;
  try {
    await redis.set('worker:deletion:heartbeat', new Date().toISOString(), 'EX', 120);
  } catch {
    // Best-effort heartbeat only.
  }
}

async function loop() {
  logger.info('Deletion worker started');
  while (running) {
    try {
      await touchHeartbeat();
      const result = await processDueDeletionRequests(20);
      if (result.processed > 0) {
        logger.info({ processed: result.processed }, 'Deletion worker processed due requests');
      }
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Deletion worker scan failed');
    }

    await new Promise((resolve) => setTimeout(resolve, config.DELETION_PROCESSOR_SCAN_SECONDS * 1000));
  }
}

async function shutdown() {
  running = false;
  logger.info('Deletion worker stopping');
  await closeRedisClient();
  await prisma.$disconnect();
}

createRedisClient();
loop().catch((error) => {
  logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Deletion worker crashed');
  process.exit(1);
});

process.on('SIGINT', () => {
  void shutdown().finally(() => process.exit(0));
});
process.on('SIGTERM', () => {
  void shutdown().finally(() => process.exit(0));
});
