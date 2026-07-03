import { createHash } from 'crypto';
import { getRedisClient } from './redis.js';
import { logger } from './logger.js';
import { incrementMetric } from './metrics.js';

export type CommunicationJobType = 'send_email' | 'send_sms' | 'send_admin_notification' | 'communication_retry' | 'provider_health_check';

export type CommunicationQueueJob =
  | {
      id: string;
      type: 'send_email';
      dedupeKey: string;
      attempts: number;
      maxAttempts: number;
      createdAt: string;
      payload: {
        subject: string;
        text: string;
        html?: string;
        recipientEmail: string;
        recipientName?: string;
        clientId?: string | null;
        locale?: string | null;
        purpose?: string | null;
        userId?: string | null;
        templateKey?: string | null;
      };
    }
  | {
      id: string;
      type: 'send_sms';
      dedupeKey: string;
      attempts: number;
      maxAttempts: number;
      createdAt: string;
      payload: {
        to: string;
        message: string;
        purpose: string;
        clientId?: string | null;
        userId?: string | null;
      };
    }
  | {
      id: string;
      type: 'send_admin_notification';
      dedupeKey: string;
      attempts: number;
      maxAttempts: number;
      createdAt: string;
      payload: {
        type: string;
        title: string;
        message: string;
        severity: string;
        category: string;
        actionUrl?: string | null;
        userId?: string | null;
        metadata?: Record<string, unknown>;
      };
    }
  | {
      id: string;
      type: 'communication_retry';
      dedupeKey: string;
      attempts: number;
      maxAttempts: number;
      createdAt: string;
      payload: { kind: 'email' | 'sms'; sourceId: string };
    }
  | {
      id: string;
      type: 'provider_health_check';
      dedupeKey: string;
      attempts: number;
      maxAttempts: number;
      createdAt: string;
      payload: { providerId?: string; channel?: 'EMAIL' | 'SMS' };
    };

const QUEUE_KEY = 'queue:communication';
const PROCESSING_KEY = 'queue:communication:processing';
const DLQ_KEY = 'queue:communication:dlq';
const DELAYED_KEY = 'queue:communication:delayed';
const DEDUPE_PREFIX = 'queue:communication:dedupe';
const STATE_PREFIX = 'queue:communication:state';
const DEFAULT_DEDUPE_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_ATTEMPTS: Record<CommunicationJobType, number> = {
  send_email: 5,
  send_sms: 5,
  send_admin_notification: 3,
  communication_retry: 3,
  provider_health_check: 3,
};

export function hashQueuePayload(input: unknown): string {
  return createHash('sha256').update(JSON.stringify(input)).digest('hex');
}

function dedupeKey(type: CommunicationJobType, payload: unknown) {
  return `${DEDUPE_PREFIX}:${type}:${hashQueuePayload(payload)}`;
}

export async function enqueueCommunicationJob(job: Omit<CommunicationQueueJob, 'id' | 'createdAt' | 'dedupeKey' | 'attempts' | 'maxAttempts'> & {
  attempts?: number;
  maxAttempts?: number;
}, dedupeTtlMs = DEFAULT_DEDUPE_TTL_MS) {
  const redis = getRedisClient();
  if (!redis) {
    logger.warn({ jobType: job.type }, 'Redis unavailable; communication job not enqueued');
    incrementMetric('queue_failure_total');
    return { queued: false, reason: 'REDIS_UNAVAILABLE' as const };
  }

  const fullJob = {
    ...job,
    id: createHash('sha256').update(`${job.type}:${Date.now()}:${Math.random()}`).digest('hex'),
    createdAt: new Date().toISOString(),
    dedupeKey: dedupeKey(job.type, job.payload),
    attempts: (job as any).attempts ?? 0,
    maxAttempts: (job as any).maxAttempts ?? DEFAULT_MAX_ATTEMPTS[job.type],
  } as CommunicationQueueJob;

  const ok = await redis.set(fullJob.dedupeKey, fullJob.id, 'PX', dedupeTtlMs, 'NX');
  if (ok !== 'OK') {
    incrementMetric('queue_enqueue_total');
    return { queued: true, deduped: true as const, jobId: fullJob.id };
  }

  try {
    await redis.lpush(QUEUE_KEY, JSON.stringify(fullJob));
  } catch (error) {
    incrementMetric('queue_failure_total');
    logger.error({ error: error instanceof Error ? error.message : String(error), jobType: job.type }, 'Failed to enqueue communication job');
    throw error;
  }
  incrementMetric('queue_enqueue_total');
  return { queued: true, deduped: false as const, jobId: fullJob.id };
}

export async function reserveNextCommunicationJob(timeoutSeconds = 5): Promise<CommunicationQueueJob | null> {
  const redis = getRedisClient();
  if (!redis) return null;
  const raw = await redis.brpoplpush(QUEUE_KEY, PROCESSING_KEY, timeoutSeconds);
  if (!raw) return null;
  const job = JSON.parse(raw) as CommunicationQueueJob;
  await redis.set(`${STATE_PREFIX}:${job.id}`, JSON.stringify({ state: 'processing', updatedAt: new Date().toISOString(), attempts: job.attempts }), 'PX', 24 * 60 * 60 * 1000);
  return job;
}

export async function acknowledgeCommunicationJob(job: CommunicationQueueJob) {
  const redis = getRedisClient();
  if (!redis) return;
  await redis.lrem(PROCESSING_KEY, 1, JSON.stringify(job));
  await redis.del(job.dedupeKey);
  await redis.set(`${STATE_PREFIX}:${job.id}`, JSON.stringify({ state: 'sent', updatedAt: new Date().toISOString(), attempts: job.attempts }), 'PX', 24 * 60 * 60 * 1000);
}

export async function moveCommunicationJobToDlq(job: CommunicationQueueJob, error: string) {
  const redis = getRedisClient();
  if (!redis) return;
  const enriched = { ...job, failedAt: new Date().toISOString(), error };
  await redis.lrem(PROCESSING_KEY, 1, JSON.stringify(job));
  await redis.lpush(DLQ_KEY, JSON.stringify(enriched));
  await redis.set(`${STATE_PREFIX}:${job.id}`, JSON.stringify({ state: 'dlq', updatedAt: new Date().toISOString(), attempts: job.attempts, error }), 'PX', 24 * 60 * 60 * 1000);
}

export async function scheduleCommunicationRetry(job: CommunicationQueueJob, delayMs: number, error?: string) {
  const redis = getRedisClient();
  if (!redis) return;
  const delayedJob = {
    ...job,
    attempts: job.attempts + 1,
    scheduledFor: new Date(Date.now() + delayMs).toISOString(),
    lastError: error ?? null,
  };
  await redis.lrem(PROCESSING_KEY, 1, JSON.stringify(job));
  await redis.zadd(DELAYED_KEY, Date.now() + delayMs, JSON.stringify(delayedJob));
  await redis.set(
    `${STATE_PREFIX}:${job.id}`,
    JSON.stringify({ state: 'retrying', updatedAt: new Date().toISOString(), attempts: delayedJob.attempts, nextRunAt: delayedJob.scheduledFor, error: error ?? null }),
    'PX',
    24 * 60 * 60 * 1000,
  );
}

export async function getCommunicationQueueDepth(): Promise<number> {
  const redis = getRedisClient();
  if (!redis) return 0;
  const [queued, processing, delayed] = await Promise.all([
    redis.llen(QUEUE_KEY),
    redis.llen(PROCESSING_KEY),
    redis.zcard(DELAYED_KEY),
  ]);
  return queued + processing + delayed;
}

export async function promoteDueCommunicationJobs(): Promise<number> {
  const redis = getRedisClient();
  if (!redis) return 0;
  const now = Date.now();
  const due = await redis.zrangebyscore(DELAYED_KEY, 0, now, 'LIMIT', 0, 50);
  if (!due.length) return 0;
  const multi = redis.multi();
  for (const raw of due) {
    multi.zrem(DELAYED_KEY, raw);
    multi.lpush(QUEUE_KEY, raw);
  }
  await multi.exec();
  return due.length;
}

export async function recoverStalledCommunicationJobs(staleAfterMs = 5 * 60 * 1000): Promise<number> {
  const redis = getRedisClient();
  if (!redis) return 0;
  const rawJobs = await redis.lrange(PROCESSING_KEY, 0, -1);
  let recovered = 0;
  for (const raw of rawJobs) {
    try {
      const job = JSON.parse(raw) as CommunicationQueueJob;
      const stateRaw = await redis.get(`${STATE_PREFIX}:${job.id}`);
      if (!stateRaw) continue;
      const state = JSON.parse(stateRaw) as { state?: string; updatedAt?: string };
      if (state.state === 'sent' || state.state === 'dlq') {
        await redis.lrem(PROCESSING_KEY, 1, raw);
        continue;
      }
      const updatedAt = state.updatedAt ? new Date(state.updatedAt).getTime() : 0;
      if (Date.now() - updatedAt >= staleAfterMs) {
        await redis.lrem(PROCESSING_KEY, 1, raw);
        await redis.lpush(QUEUE_KEY, raw);
        recovered += 1;
      }
    } catch {
      // Ignore malformed entries and let the next pass clean up what it can.
    }
  }
  return recovered;
}
