import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { logger } from './logger.js';
import { redactPrismaParams } from './redactPrismaParams.js';

export { redactPrismaParams };

const adapter = new PrismaPg({ connectionString: process.env['DATABASE_URL']! });

export const prisma = new PrismaClient({
  adapter,
  log: [
    { emit: 'event', level: 'query' },
    { emit: 'stdout', level: 'info' },
    { emit: 'stdout', level: 'warn' },
    { emit: 'stdout', level: 'error' },
  ],
});

// @ts-ignore
prisma.$on('query', (e: any) => {
  if (process.env.PRISMA_QUERY_LOG === 'true') {
    const safeParams = redactPrismaParams(e.params);
    if (process.env.NODE_ENV === 'development') {
      console.log(`\n${new Date().toLocaleTimeString()} DB [wpa-auth-api] Query ${e.duration}ms\n\nSQL:\n  ${e.query}\n\nParameters (redacted):\n  ${safeParams}\n`);
    } else {
      logger.debug({ query: e.query, params: safeParams, duration: `${e.duration}ms` }, 'Prisma Query');
    }
  }
});
