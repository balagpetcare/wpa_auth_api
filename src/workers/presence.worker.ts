import { logger } from '../lib/logger.js';
import { closeRedisClient, createRedisClient } from '../lib/redis.js';
import { prisma } from '../lib/db.js';
import { flushPresenceLastSeen } from '../lib/presence.js';

let running = true;

async function loop() {
  logger.info('Presence worker started');
  while (running) {
    try {
      const result = await flushPresenceLastSeen(250);
      if (result.flushed > 0) {
        logger.info({ flushed: result.flushed }, 'Presence lastSeenAt batch flushed');
      }
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Presence worker flush failed');
    }

    await new Promise((resolve) => setTimeout(resolve, 30_000));
  }
}

async function shutdown() {
  running = false;
  logger.info('Presence worker stopping');
  await closeRedisClient();
  await prisma.$disconnect();
}

createRedisClient();
loop().catch((error) => {
  logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Presence worker crashed');
  process.exit(1);
});

process.on('SIGINT', () => {
  void shutdown().finally(() => process.exit(0));
});
process.on('SIGTERM', () => {
  void shutdown().finally(() => process.exit(0));
});
