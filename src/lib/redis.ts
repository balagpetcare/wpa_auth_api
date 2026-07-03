import { Redis } from 'ioredis';

let _client: Redis | null = null;

export function getRedisClient(): Redis | null {
  return _client;
}

export function createRedisClient(): Redis | null {
  const url = process.env.REDIS_URL;
  if (!url) {
    if (process.env.NODE_ENV === 'production') {
      console.error('FATAL: REDIS_URL is required in production. Exiting.');
      process.exit(1);
    }
    console.warn('WARNING: REDIS_URL not set. Using in-memory rate limiting. Not suitable for production.');
    return null;
  }

  const client = new (Redis as any)(url, {
    maxRetriesPerRequest: 0,
    enableReadyCheck: false,
    lazyConnect: false,
    // Without a command timeout, queued commands can hang indefinitely during a Redis
    // outage/reconnect (observed live: requests to enterpriseRateLimit-protected routes
    // hung 30s+ and never resolved even after Redis came back up). This bounds every
    // command so callers relying on try/catch fail-open behavior actually get an error.
    //
    // Must stay comfortably above the longest blocking command timeout used anywhere
    // on this client — reserveNextCommunicationJob() issues BRPOPLPUSH with a 5s
    // server-side block (communicationQueue.ts). A commandTimeout shorter than that
    // (previously 1500ms) fires while the blocking pop is still legitimately waiting
    // for a job, throwing "Command timed out" on every idle poll — this crashed the
    // communication worker's main loop (uncaught, no queued jobs) within ~2s of
    // startup. 7000ms leaves margin above the 5s block while still bounding genuine
    // Redis-outage hangs for the fast-path rate-limit commands.
    commandTimeout: 7000,
  }) as Redis;

  client.on('error', (err: Error) => {
    console.error('Redis client error:', err.message);
  });

  client.on('connect', () => {
    console.info('Redis connected');
  });

  _client = client;
  return client;
}

export async function closeRedisClient(): Promise<void> {
  if (_client) {
    await _client.quit();
    _client = null;
  }
}
