import { createHash } from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { getRedisClient } from './redis.js';
import { AppError } from './errors.js';
import { Prisma } from '@prisma/client';
import { writeSecurityEvent } from './audit.js';
import { createAdminNotification } from './adminNotifications.js';

type ThreatKind =
  | 'RATE_LIMIT_BLOCKED'
  | 'TEMPORARY_BLOCK_APPLIED'
  | 'ADMIN_LOGIN_ABUSE'
  | 'OAUTH_CLIENT_SECRET_ABUSE'
  | 'OTP_ABUSE_DETECTED'
  | 'PASSWORD_RESET_ABUSE'
  | 'BOT_TRAFFIC_SPIKE'
  | 'REFRESH_TOKEN_REUSE_DETECTED'
  | 'SUSPICIOUS_ACTIVITY_BLOCKED';

type RateLimitOptions = {
  route: string;
  windowMs: number;
  max: number;
  identifierFrom?: (req: Request) => string | undefined;
  blockAfter?: number;
  blockTtlMs?: number;
  threat?: ThreatKind;
};

const DEFAULT_BLOCK_TTL_MS = 30 * 60 * 1000;
const DEFAULT_RISK_TTL_MS = 15 * 60 * 1000;

export function getClientIp(req: Request): string {
  const forwarded = typeof req.headers['x-forwarded-for'] === 'string'
    ? req.headers['x-forwarded-for'].split(',')[0]?.trim()
    : undefined;
  return forwarded || req.ip || req.socket.remoteAddress || 'unknown';
}

export function hashAbuseValue(value: string): string {
  return createHash('sha256').update(value.trim().toLowerCase()).digest('hex');
}

function ipBlockKey(ip: string) {
  return `abuse:block:${ip}`;
}

function identifierBlockKey(identifier: string) {
  return `abuse:block:identifier:${hashAbuseValue(identifier)}`;
}

function riskKey(ip: string) {
  return `abuse:risk:${ip}`;
}

async function emitThreatEvent(req: Request, threat: ThreatKind, metadata: Record<string, unknown>) {
  try {
    await writeSecurityEvent({
      type: 'BRUTE_FORCE_DETECTED',
      severity: 'HIGH',
      metadata: { threat, ...metadata } as Prisma.InputJsonValue,
      req,
    });
  } catch (err) {
    console.error('Failed to write abuse security event:', err);
  }

  if (threat === 'ADMIN_LOGIN_ABUSE' || threat === 'BOT_TRAFFIC_SPIKE' || threat === 'SUSPICIOUS_ACTIVITY_BLOCKED') {
    try {
    await createAdminNotification({
        type: threat,
        title: 'Suspicious activity detected',
        message: 'Temporary abuse protection was triggered for one or more admin or public auth routes.',
        severity: 'SECURITY',
        category: 'SECURITY',
        actionUrl: '/security-events',
        metadata: metadata as Prisma.InputJsonValue,
      });
    } catch (err) {
      console.error('Failed to write abuse admin notification:', err);
    }
  }
}

async function applyBlock(req: Request, route: string, ip: string, identifier?: string, threat: ThreatKind = 'SUSPICIOUS_ACTIVITY_BLOCKED', ttlMs = DEFAULT_BLOCK_TTL_MS) {
  const redis = getRedisClient();
  if (!redis) return;

  const multi = redis.multi();
  multi.set(ipBlockKey(ip), route, 'PX', ttlMs);
  if (identifier) {
    multi.set(identifierBlockKey(identifier), route, 'PX', ttlMs);
  }
  await multi.exec();
  await emitThreatEvent(req, threat, {
    route,
    ip,
    ...(identifier ? { identifierHash: hashAbuseValue(identifier) } : {}),
    blockTtlMs: ttlMs,
  });
}

export async function noteRiskAndMaybeBlock(opts: {
  route: string;
  req: Request;
  identifier?: string;
  userId?: string;
  clientId?: string;
  threat?: ThreatKind;
  ttlMs?: number;
  blockAfter?: number;
  blockTtlMs?: number;
}) {
  const redis = getRedisClient();
  if (!redis) return;
  const ip = getClientIp(opts.req);
  const key = riskKey(ip);
  try {
    const current = await redis.incr(key);
    if (current === 1) {
      await redis.pexpire(key, opts.ttlMs ?? DEFAULT_RISK_TTL_MS);
    }
    if (current >= (opts.blockAfter ?? 8)) {
      await applyBlock(opts.req, opts.route, ip, opts.identifier, opts.threat ?? 'BOT_TRAFFIC_SPIKE', opts.blockTtlMs ?? DEFAULT_BLOCK_TTL_MS);
    }
  } catch (err) {
    console.error('noteRiskAndMaybeBlock redis error, failing open:', err);
  }
}

export async function clearRisk(opts: { req: Request; identifier?: string }) {
  const redis = getRedisClient();
  if (!redis) return;
  try {
    await redis.del(riskKey(getClientIp(opts.req)));
    if (opts.identifier) {
      await redis.del(identifierBlockKey(opts.identifier));
    }
  } catch (err) {
    console.error('clearRisk redis error, ignoring:', err);
  }
}

export async function isTemporarilyBlocked(req: Request, identifier?: string): Promise<boolean> {
  const redis = getRedisClient();
  if (!redis) return false;
  const ip = getClientIp(req);
  try {
    if (await redis.exists(ipBlockKey(ip))) return true;
    if (identifier && await redis.exists(identifierBlockKey(identifier))) return true;
    return false;
  } catch (err) {
    console.error('isTemporarilyBlocked redis error, failing open:', err);
    return false;
  }
}

export function enterpriseRateLimit(opts: RateLimitOptions) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const redis = getRedisClient();
    const ip = getClientIp(req);
    const identifier = opts.identifierFrom?.(req)?.trim();
    if (await isTemporarilyBlocked(req, identifier)) {
      res.status(429).json({ success: false, message: 'Request temporarily blocked due to suspicious activity.', code: 'TEMPORARILY_BLOCKED' });
      return;
    }

    if (!redis) {
      return next();
    }

    const windowSeconds = Math.ceil(opts.windowMs / 1000);
    const ipKey = `rl:ip:${opts.route}:${ip}`;
    const keys = [ipKey];
    if (identifier) keys.push(`rl:identifier:${opts.route}:${hashAbuseValue(identifier)}`);

    try {
      const counts = await Promise.all(keys.map((key) => redis.incr(key)));
      await Promise.all(keys.map((key) => redis.ttl(key).then((ttl) => ttl === -1 ? redis.expire(key, windowSeconds) : null)));

      const max = opts.max;
      if (counts.some((count) => count > max)) {
        await noteRiskAndMaybeBlock({
          route: opts.route,
          req,
          identifier,
          threat: opts.threat ?? 'RATE_LIMIT_BLOCKED',
          blockAfter: opts.blockAfter ?? max + 4,
          blockTtlMs: opts.blockTtlMs ?? DEFAULT_BLOCK_TTL_MS,
        });
        res.status(429).json({ success: false, message: 'Too many requests, please try again later.', code: 'RATE_LIMITED' });
        return;
      }
      next();
    } catch (err) {
      console.error('Enterprise rate limit error', err);
      next();
    }
  };
}

export async function logAbuseSignal(opts: {
  route: string;
  req: Request;
  identifier?: string;
  userId?: string;
  clientId?: string;
  threat?: ThreatKind;
  blockAfter?: number;
  blockTtlMs?: number;
}) {
  await noteRiskAndMaybeBlock({
    route: opts.route,
    req: opts.req,
    identifier: opts.identifier,
    userId: opts.userId,
    clientId: opts.clientId,
    threat: opts.threat,
    blockAfter: opts.blockAfter,
    blockTtlMs: opts.blockTtlMs,
  });
}

export function captchaRequired(): boolean {
  return process.env.CAPTCHA_REQUIRED_ON_HIGH_RISK === 'true';
}
