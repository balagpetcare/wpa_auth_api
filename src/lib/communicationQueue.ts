import { createHash } from 'crypto';
import { getRedisClient } from './redis.js';
import { logger } from './logger.js';

export type CommunicationJobType = 'send_email' | 'send_sms' | 'send_admin_notification' | 'communication_retry' | 'provider_health_check';

export type CommunicationQueueJob =
  | {
      id: string;
      type: 'send_email';
      dedupeKey: string;
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
      };
    }
  | {
      id: string;
      type: 'send_sms';
      dedupeKey: string;
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
      createdAt: string;
      payload: { kind: 'email' | 'sms'; sourceId: string };
    }
  | {
      id: string;
      type: 'provider_health_check';
      dedupeKey: string;
      createdAt: string;
      payload: { providerId?: string; channel?: 'EMAIL' | 'SMS' };
    };

const QUEUE_KEY = 'queue:communication';
const PROCESSING_KEY = 'queue:communication:processing';
const DLQ_KEY = 'queue:communication:dlq';
const DEDUPE_PREFIX = 'queue:communication:dedupe';
const DEFAULT_DEDUPE_TTL_MS = 24 * 60 * 60 * 1000;

export function hashQueuePayload(input: unknown): string {
  return createHash('sha256').update(JSON.stringify(input)).digest('hex');
}

function dedupeKey(type: CommunicationJobType, payload: unknown) {
  return `${DEDUPE_PREFIX}:${type}:${hashQueuePayload(payload)}`;
}

export async function enqueueCommunicationJob(job: Omit<CommunicationQueueJob, 'id' | 'createdAt' | 'dedupeKey'>, dedupeTtlMs = DEFAULT_DEDUPE_TTL_MS) {
  const redis = getRedisClient();
  if (!redis) {
    logger.warn({ jobType: job.type }, 'Redis unavailable; communication job not enqueued');
    return { queued: false, reason: 'REDIS_UNAVAILABLE' as const };
  }

  const fullJob = {
    ...job,
    id: createHash('sha256').update(`${job.type}:${Date.now()}:${Math.random()}`).digest('hex'),
    createdAt: new Date().toISOString(),
    dedupeKey: dedupeKey(job.type, job.payload),
  } as CommunicationQueueJob;

  const ok = await redis.set(fullJob.dedupeKey, fullJob.id, 'PX', dedupeTtlMs, 'NX');
  if (ok !== 'OK') {
    return { queued: true, deduped: true as const, jobId: fullJob.id };
  }

  await redis.lpush(QUEUE_KEY, JSON.stringify(fullJob));
  return { queued: true, deduped: false as const, jobId: fullJob.id };
}

export async function reserveNextCommunicationJob(timeoutSeconds = 5): Promise<CommunicationQueueJob | null> {
  const redis = getRedisClient();
  if (!redis) return null;
  const raw = await redis.brpoplpush(QUEUE_KEY, PROCESSING_KEY, timeoutSeconds);
  if (!raw) return null;
  return JSON.parse(raw) as CommunicationQueueJob;
}

export async function acknowledgeCommunicationJob(job: CommunicationQueueJob) {
  const redis = getRedisClient();
  if (!redis) return;
  await redis.lrem(PROCESSING_KEY, 1, JSON.stringify(job));
  await redis.del(job.dedupeKey);
}

export async function moveCommunicationJobToDlq(job: CommunicationQueueJob, error: string) {
  const redis = getRedisClient();
  if (!redis) return;
  const enriched = { ...job, failedAt: new Date().toISOString(), error };
  await redis.lrem(PROCESSING_KEY, 1, JSON.stringify(job));
  await redis.lpush(DLQ_KEY, JSON.stringify(enriched));
}

export async function getCommunicationQueueDepth(): Promise<number> {
  const redis = getRedisClient();
  if (!redis) return 0;
  return redis.llen(QUEUE_KEY);
}
