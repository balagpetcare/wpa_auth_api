import { createRedisClient, closeRedisClient } from '../lib/redis.js';
import { prisma } from '../lib/db.js';
import { runRetentionPruning } from '../services/retentionPruning.service.js';
import { logger } from '../lib/logger.js';

async function main() {
  const args = new Set(process.argv.slice(2));
  const dryRun = args.has('--dry-run');
  const batchArg = process.argv.find((arg) => arg.startsWith('--batch-size='));
  const batchSize = batchArg ? Number(batchArg.split('=')[1]) : undefined;

  createRedisClient();

  try {
    const results = await runRetentionPruning({ dryRun, batchSize });
    for (const result of results) {
      console.log(`${result.name}: candidates=${result.candidates} deleted=${result.deleted}`);
    }
    logger.info({ dryRun, batchSize }, 'Retention pruning completed');
  } finally {
    await closeRedisClient();
    await prisma.$disconnect();
  }
}

main().catch((error) => {
  logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Retention pruning failed');
  process.exit(1);
});
