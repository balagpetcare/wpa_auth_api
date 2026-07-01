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
