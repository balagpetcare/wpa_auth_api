import { getRedisClient } from './redis.js';
import { prisma } from './db.js';
import { config } from '../config/index.js';

const DIRTY_SET_KEY = 'presence:dirty';

function keyForApp(appId: string, userId: string) {
  return `presence:${appId}:${userId}`;
}

function anyKey(userId: string) {
  return `presence:any:${userId}`;
}

function touchedKey(userId: string) {
  return `presence:touched:${userId}`;
}

export async function recordPresenceHeartbeat(opts: { userId: string; appId?: string | null; ttlSeconds?: number; now?: number }) {
  const redis = getRedisClient();
  if (!redis) {
    return { recorded: false as const, reason: 'REDIS_UNAVAILABLE' as const };
  }
  const ttlSeconds = opts.ttlSeconds ?? config.PRESENCE_TTL_SECONDS;
  const now = opts.now ?? Date.now();
  const cooldownKey = `presence:cooldown:${opts.appId ?? 'any'}:${opts.userId}`;
  const cooldown = await redis.set(cooldownKey, String(now), 'EX', config.PRESENCE_HEARTBEAT_MIN_INTERVAL_SECONDS, 'NX');
  if (cooldown !== 'OK') {
    return { recorded: false as const, reason: 'COOLDOWN' as const };
  }

  const multi = redis.multi();
  multi.set(anyKey(opts.userId), opts.appId ?? 'any', 'EX', ttlSeconds);
  if (opts.appId) {
    multi.set(keyForApp(opts.appId, opts.userId), '1', 'EX', ttlSeconds);
    multi.sadd(`presence:apps:${opts.userId}`, opts.appId);
    multi.expire(`presence:apps:${opts.userId}`, ttlSeconds);
  }
  multi.zadd(DIRTY_SET_KEY, now, opts.userId);
  multi.set(touchedKey(opts.userId), String(now), 'EX', ttlSeconds);
  await multi.exec();
  return { recorded: true as const, ttlSeconds };
}

export async function getPresenceSummary(userId: string) {
  const redis = getRedisClient();
  if (!redis) {
    return { onlineNow: false, appsOnline: [], lastSeenAny: null };
  }
  const appIds = await redis.smembers(`presence:apps:${userId}`);
  const appStatuses = await Promise.all(appIds.map(async (appId) => ({ appId, online: await redis.exists(keyForApp(appId, userId)) === 1 })));
  const appsOnline = appStatuses.filter((item) => item.online).map((item) => item.appId);
  const onlineNow = (await redis.exists(anyKey(userId))) === 1;
  const lastSeenAny = await redis.get(touchedKey(userId));
  return { onlineNow, appsOnline, lastSeenAny };
}

export async function flushPresenceLastSeen(batchSize = 100) {
  const redis = getRedisClient();
  if (!redis) return { flushed: 0 };
  const userIds = await redis.zrange(DIRTY_SET_KEY, 0, batchSize - 1);
  if (!userIds.length) return { flushed: 0 };
  const touchedKeys = userIds.map((userId) => touchedKey(userId));
  const touchedValues = await redis.mget(...touchedKeys);

  const updates: Promise<unknown>[] = [];
  const pipeline = redis.multi();

  for (let i = 0; i < userIds.length; i += 1) {
    const userId = userIds[i];
    const rawSeenAt = touchedValues[i];
    const seenAtMs = rawSeenAt ? Number(rawSeenAt) : NaN;
    if (Number.isFinite(seenAtMs)) {
      updates.push(
        prisma.user.update({
          where: { id: userId },
          data: { lastSeenAt: new Date(seenAtMs) },
          select: { id: true },
        }).catch(() => null),
      );
    }
    pipeline.zrem(DIRTY_SET_KEY, userId);
    pipeline.del(touchedKey(userId));
  }

  await Promise.all(updates);
  await pipeline.exec();
  return { flushed: userIds.length };
}

export function getPresenceTtlSeconds() {
  return config.PRESENCE_TTL_SECONDS;
}

export function getPresenceCooldownSeconds() {
  return config.PRESENCE_HEARTBEAT_MIN_INTERVAL_SECONDS;
}
