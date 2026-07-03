import dotenv from 'dotenv';
dotenv.config();

import { createHash } from 'crypto';
import { createRedisClient, getRedisClient } from '../lib/redis.js';

function hashAbuseValue(value: string): string {
  return createHash('sha256').update(value.trim().toLowerCase()).digest('hex');
}

function argValue(name: string): string | undefined {
  const prefix = `--${name}=`;
  const arg = process.argv.find((item) => item.startsWith(prefix));
  return arg ? arg.slice(prefix.length) : undefined;
}

async function main() {
  const emailOrUsername = argValue('identifier') ?? process.env.AUTH_ABUSE_IDENTIFIER;
  const ip = argValue('ip') ?? process.env.AUTH_ABUSE_IP;

  if (!ip && !emailOrUsername) {
    console.error('Provide --ip and/or --identifier to clear a specific local abuse block.');
    process.exit(1);
  }

  const redis = getRedisClient() ?? createRedisClient();
  if (!redis) {
    console.error('REDIS_URL is required for this cleanup helper.');
    process.exit(1);
  }

  const keys: string[] = [];
  if (ip) {
    keys.push(`abuse:block:${ip}`);
    keys.push(`abuse:risk:${ip}`);
  }
  if (emailOrUsername) {
    const identifier = ip ? `${emailOrUsername}:${ip}` : emailOrUsername;
    keys.push(`abuse:block:identifier:${hashAbuseValue(identifier)}`);
  }

  if (keys.length === 0) {
    process.exit(0);
  }

  await redis.del(...keys);
  console.log(`Deleted abuse keys: ${keys.join(', ')}`);
  await redis.quit();
}

main().catch(async (err) => {
  console.error('Failed to clear abuse keys:', err);
  const redis = getRedisClient();
  if (redis) {
    await redis.quit().catch(() => undefined);
  }
  process.exit(1);
});
