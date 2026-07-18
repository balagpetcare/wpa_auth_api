import { createHash } from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { CommunicationChannel, OtpTemplatePurpose, Prisma } from '@prisma/client';
import { getRedisClient } from './redis.js';
import { AppError } from './errors.js';
import { writeSecurityEvent } from './audit.js';
import { enqueueCommunicationJob } from './communicationQueue.js';
import { incrementMetric } from './metrics.js';
import { config } from '../config/index.js';
import { logger } from './logger.js';

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
  blockScope?: 'ip' | 'identifier' | 'both';
};

const DEFAULT_BLOCK_TTL_MS = 30 * 60 * 1000;
const DEFAULT_RISK_TTL_MS = 15 * 60 * 1000;
const COMMUNICATION_RECIPIENT_15M_LIMIT = 3;
const COMMUNICATION_RECIPIENT_HOURLY_LIMIT = 5;
const COMMUNICATION_RECIPIENT_DAILY_LIMIT = 10;
const COMMUNICATION_IP_HOURLY_LIMIT = 20;
const COMMUNICATION_USER_HOURLY_LIMIT = 10;
const COMMUNICATION_USER_DAILY_LIMIT = 20;
const COMMUNICATION_PROVIDER_TEST_RECIPIENT_HOURLY_LIMIT = 5;
const COMMUNICATION_PROVIDER_TEST_PROVIDER_HOURLY_LIMIT = 20;
const COMMUNICATION_MANUAL_RETRY_ADMIN_HOURLY_LIMIT = 20;
const COMMUNICATION_MANUAL_RETRY_PROVIDER_HOURLY_LIMIT = 20;
const COMMUNICATION_CAPPED_BLOCK_TTL_MS = 60 * 60 * 1000;

export type CommunicationAbuseContext = 'send' | 'retry' | 'provider_test' | 'admin_invite';

export type CommunicationAbuseLimitInput = {
  channel: CommunicationChannel;
  purpose: OtpTemplatePurpose | 'GENERAL';
  recipient: string;
  req?: Request;
  userId?: string | null;
  actorAdminId?: string | null;
  providerId?: string | null;
  context?: CommunicationAbuseContext;
  bodyLength?: number;
  templateKey?: string;
};

export type CommunicationAbuseDecision =
  | { allowed: true }
  | {
      allowed: false;
      code: 'COMMUNICATION_RATE_LIMITED' | 'COMMUNICATION_BLOCKED' | 'VALIDATION_ERROR';
      message: string;
      limitName: string;
      retryAfterMs?: number;
    };

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

function communicationBlockKey(scope: 'recipient' | 'recipient-ip' | 'provider' | 'admin', hash: string) {
  return `abuse:block:communication:${scope}:${hash}`;
}

function communicationCounterKey(scope: string) {
  return `abuse:communication:${scope}`;
}

function isLocalDevIp(ip: string) {
  return ['127.0.0.1', '::1', '::ffff:127.0.0.1', 'localhost', 'unknown'].includes(ip);
}

function useRelaxedDevAbuseRules(ip: string) {
  return process.env.NODE_ENV !== 'production'
    && process.env.AUTH_ABUSE_DEV_RELAXED !== 'false'
    && isLocalDevIp(ip);
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
    logger.error({ error: err instanceof Error ? err.message : String(err) }, 'Failed to write abuse security event');
  }

  if (threat === 'ADMIN_LOGIN_ABUSE' || threat === 'BOT_TRAFFIC_SPIKE' || threat === 'SUSPICIOUS_ACTIVITY_BLOCKED') {
    try {
      await enqueueCommunicationJob({
        type: 'send_admin_notification',
        payload: {
          type: threat,
          title: 'Suspicious activity detected',
          message: 'Temporary abuse protection was triggered for one or more admin or public auth routes.',
          severity: 'WARNING',
          category: 'SECURITY',
          actionUrl: '/security-events',
          metadata: metadata as Record<string, unknown>,
        },
      });
    } catch (err) {
      logger.error({ error: err instanceof Error ? err.message : String(err) }, 'Failed to write abuse admin notification');
    }
  }
}

function normalizeCommunicationRecipient(channel: CommunicationChannel, recipient: string) {
  const trimmed = recipient.trim();
  if (channel === 'EMAIL') {
    return trimmed.toLowerCase();
  }

  let cleaned = trimmed.replace(/[^\d+]/g, '');
  if (!cleaned.startsWith('+') && cleaned.startsWith('01') && cleaned.length === 11) {
    cleaned = '+88' + cleaned;
  } else if (!cleaned.startsWith('+')) {
    cleaned = '+' + cleaned;
  }
  return cleaned;
}

async function bumpWindow(redis: NonNullable<ReturnType<typeof getRedisClient>>, key: string, ttlMs: number, limit: number) {
  const current = await redis.incr(key);
  if (current === 1) {
    await redis.pexpire(key, ttlMs);
  }
  return current <= limit;
}

async function recordCommunicationBlock(input: CommunicationAbuseLimitInput & {
  limitName: string;
  reason: string;
  retryAfterMs?: number;
}) {
  const redis = getRedisClient();
  const ip = input.req ? getClientIp(input.req) : undefined;
  if (redis) {
    const normalizedRecipient = normalizeCommunicationRecipient(input.channel, input.recipient);
    const recipientHash = hashAbuseValue(normalizedRecipient);
    const scopeHash = `${recipientHash}${ip ? `:${hashAbuseValue(ip)}` : ''}`;
    const multi = redis.multi();
    multi.set(communicationBlockKey('recipient', recipientHash), input.limitName, 'PX', input.retryAfterMs ?? COMMUNICATION_CAPPED_BLOCK_TTL_MS);
    if (ip && !useRelaxedDevAbuseRules(ip)) {
      multi.set(communicationBlockKey('recipient-ip', scopeHash), input.limitName, 'PX', input.retryAfterMs ?? COMMUNICATION_CAPPED_BLOCK_TTL_MS);
    }
    if (input.providerId) {
      multi.set(communicationBlockKey('provider', `${input.providerId}:${recipientHash}`), input.limitName, 'PX', input.retryAfterMs ?? COMMUNICATION_CAPPED_BLOCK_TTL_MS);
    }
    if (input.actorAdminId) {
      multi.set(communicationBlockKey('admin', `${input.actorAdminId}:${recipientHash}`), input.limitName, 'PX', input.retryAfterMs ?? COMMUNICATION_CAPPED_BLOCK_TTL_MS);
    }
    await multi.exec();
  }

  incrementMetric('rate_limit_block_total');
  logger.warn(
    {
      area: 'communication',
      context: input.context,
      channel: input.channel,
      purpose: input.purpose,
      limitName: input.limitName,
      recipientHash: hashAbuseValue(normalizeCommunicationRecipient(input.channel, input.recipient)),
      providerId: input.providerId ?? null,
    },
    'Communication abuse limit exceeded, blocking send',
  );
  try {
    await writeSecurityEvent({
      type: 'BRUTE_FORCE_DETECTED',
      severity: 'HIGH',
      metadata: {
        area: 'communication',
        context: input.context,
        channel: input.channel,
        purpose: input.purpose,
        limitName: input.limitName,
        recipientHash: hashAbuseValue(normalizeCommunicationRecipient(input.channel, input.recipient)),
        providerId: input.providerId ?? null,
        userId: input.userId ?? null,
        actorAdminId: input.actorAdminId ?? null,
        ip: ip ?? null,
        reason: input.reason,
      } as Prisma.InputJsonValue,
      req: input.req,
    });
  } catch (err) {
    logger.error({ error: err instanceof Error ? err.message : String(err) }, 'Failed to write communication abuse security event');
  }
}

export async function checkCommunicationAbuseLimits(input: CommunicationAbuseLimitInput): Promise<CommunicationAbuseDecision> {
  if (typeof input.bodyLength === 'number' && input.bodyLength > 2000) {
    return {
      allowed: false,
      code: 'VALIDATION_ERROR',
      message: 'Test message is too long.',
      limitName: 'body_length',
    };
  }

  if (!config.COMMUNICATION_RATE_LIMIT_ENABLED) {
    return { allowed: true };
  }

  const redis = getRedisClient();
  if (!redis) {
    return { allowed: true };
  }

  const ip = input.req ? getClientIp(input.req) : undefined;
  if (ip && useRelaxedDevAbuseRules(ip)) {
    return { allowed: true };
  }

  const normalizedRecipient = normalizeCommunicationRecipient(input.channel, input.recipient);
  const recipientHash = hashAbuseValue(normalizedRecipient);
  const userHash = input.userId ? hashAbuseValue(String(input.userId)) : null;
  const ipHash = ip ? hashAbuseValue(ip) : null;
  const scopedIpRecipientKey = ipHash ? communicationBlockKey('recipient-ip', `${recipientHash}:${ipHash}`) : null;

  const isSecurityAlert = input.templateKey === 'login_alert' || input.templateKey === 'security_alert';
  const blockMessage = isSecurityAlert 
    ? 'Communication blocked (security alert suppressed).' 
    : 'Please wait before requesting another code.';

  try {
    if (await redis.exists(communicationBlockKey('recipient', recipientHash))) {
      return {
        allowed: false,
        code: 'COMMUNICATION_BLOCKED',
        message: blockMessage,
        limitName: 'recipient_block',
      };
    }
    if (scopedIpRecipientKey && await redis.exists(scopedIpRecipientKey)) {
      return {
        allowed: false,
        code: 'COMMUNICATION_BLOCKED',
        message: blockMessage,
        limitName: 'ip_recipient_block',
      };
    }
    if (input.providerId && await redis.exists(communicationBlockKey('provider', `${input.providerId}:${recipientHash}`))) {
      return {
        allowed: false,
        code: 'COMMUNICATION_BLOCKED',
        message: 'Please wait before sending another test message.',
        limitName: 'provider_block',
      };
    }
    if (input.actorAdminId && await redis.exists(communicationBlockKey('admin', `${input.actorAdminId}:${recipientHash}`))) {
      return {
        allowed: false,
        code: 'COMMUNICATION_BLOCKED',
        message: input.context === 'retry' ? 'Please wait before retrying this delivery.' : 'Please wait before sending another test message.',
        limitName: 'admin_block',
      };
    }
  } catch (err) {
    logger.error({ error: err instanceof Error ? err.message : String(err) }, 'Communication abuse block check failed, failing open');
    return { allowed: true };
  }

  let windows: Array<{ key: string; ttlMs: number; limit: number; limitName: string; message: string }> = [];
  
  if (isSecurityAlert) {
    windows.push({
      key: communicationCounterKey(`${input.channel}:security_alert:recipient:${recipientHash}:15m`),
      ttlMs: 15 * 60 * 1000,
      limit: 3,
      limitName: 'security_alert_15m',
      message: 'Security alert suppressed to prevent spam.',
    });
  } else {
    windows = [
      {
        key: communicationCounterKey(`${input.channel}:${input.purpose}:recipient:${recipientHash}:15m`),
        ttlMs: 15 * 60 * 1000,
        limit: COMMUNICATION_RECIPIENT_15M_LIMIT,
        limitName: 'recipient_15m',
        message: 'Please wait before requesting another code.',
      },
      {
        key: communicationCounterKey(`${input.channel}:${input.purpose}:recipient:${recipientHash}:1h`),
        ttlMs: 60 * 60 * 1000,
        limit: input.channel === 'SMS'
          ? config.COMMUNICATION_MAX_SMS_PER_PHONE_PER_HOUR
          : config.COMMUNICATION_MAX_EMAIL_PER_ADDRESS_PER_HOUR,
        limitName: 'recipient_1h',
        message: 'Please wait before requesting another code.',
      },
      {
        key: communicationCounterKey(`${input.channel}:${input.purpose}:recipient:${recipientHash}:1d`),
        ttlMs: 24 * 60 * 60 * 1000,
        limit: input.channel === 'SMS'
          ? config.COMMUNICATION_MAX_SMS_PER_PHONE_PER_DAY
          : config.COMMUNICATION_MAX_EMAIL_PER_ADDRESS_PER_DAY,
        limitName: 'recipient_1d',
        message: 'Please wait before requesting another code.',
      },
    ];
  }

  if (ipHash) {
    windows.push({
      key: communicationCounterKey(`${input.channel}:ip:${ipHash}:1h`),
      ttlMs: 60 * 60 * 1000,
      limit: COMMUNICATION_IP_HOURLY_LIMIT,
      limitName: 'ip_1h',
      message: blockMessage,
    });
    windows.push({
      key: communicationCounterKey(`${input.channel}:${input.purpose}:pair:${ipHash}:${recipientHash}:15m`),
      ttlMs: 15 * 60 * 1000,
      limit: COMMUNICATION_RECIPIENT_15M_LIMIT,
      limitName: 'ip_recipient_15m',
      message: blockMessage,
    });
  }

  if (userHash) {
    windows.push({
      key: communicationCounterKey(`${input.channel}:user:${userHash}:1h`),
      ttlMs: 60 * 60 * 1000,
      limit: COMMUNICATION_USER_HOURLY_LIMIT,
      limitName: 'user_1h',
      message: blockMessage,
    });
    windows.push({
      key: communicationCounterKey(`${input.channel}:user:${userHash}:1d`),
      ttlMs: 24 * 60 * 60 * 1000,
      limit: COMMUNICATION_USER_DAILY_LIMIT,
      limitName: 'user_1d',
      message: blockMessage,
    });
  }

  const systemLimitMessage = input.templateKey === 'login_alert' 
    ? 'System communication limit reached (alerts suppressed).' 
    : 'Please wait before requesting another code.';

  windows.push({
    key: communicationCounterKey(`${input.channel}:system:1h`),
    ttlMs: 60 * 60 * 1000,
    limit: input.channel === 'SMS'
      ? config.COMMUNICATION_SYSTEM_SMS_HOURLY_CAP
      : config.COMMUNICATION_SYSTEM_EMAIL_HOURLY_CAP,
    limitName: 'system_1h',
    message: systemLimitMessage,
  });
  windows.push({
    key: communicationCounterKey(`${input.channel}:system:1d`),
    ttlMs: 24 * 60 * 60 * 1000,
    limit: input.channel === 'SMS'
      ? config.COMMUNICATION_SYSTEM_SMS_DAILY_CAP
      : config.COMMUNICATION_SYSTEM_EMAIL_DAILY_CAP,
    limitName: 'system_1d',
    message: systemLimitMessage,
  });

  if (input.context === 'provider_test') {
    if (input.actorAdminId) {
      windows.push({
        key: communicationCounterKey(`${input.channel}:provider-test:admin:${hashAbuseValue(input.actorAdminId)}:1h`),
        ttlMs: 60 * 60 * 1000,
        limit: config.COMMUNICATION_MAX_PROVIDER_TEST_PER_ADMIN_HOUR,
        limitName: 'admin_test_1h',
        message: 'Please wait before sending another test message.',
      });
    }
    if (input.providerId) {
      windows.push({
        key: communicationCounterKey(`${input.channel}:provider-test:provider:${input.providerId}:1h`),
        ttlMs: 60 * 60 * 1000,
        limit: COMMUNICATION_PROVIDER_TEST_PROVIDER_HOURLY_LIMIT,
        limitName: 'provider_test_1h',
        message: 'Please wait before sending another test message.',
      });
    }
    windows.push({
      key: communicationCounterKey(`${input.channel}:provider-test:recipient:${recipientHash}:1h`),
      ttlMs: 60 * 60 * 1000,
      limit: COMMUNICATION_PROVIDER_TEST_RECIPIENT_HOURLY_LIMIT,
      limitName: 'provider_test_recipient_1h',
      message: 'Please wait before sending another test message.',
    });
  }

  if (input.context === 'retry' && input.actorAdminId) {
    windows.push({
      key: communicationCounterKey(`${input.channel}:retry:admin:${hashAbuseValue(input.actorAdminId)}:1h`),
      ttlMs: 60 * 60 * 1000,
      limit: COMMUNICATION_MANUAL_RETRY_ADMIN_HOURLY_LIMIT,
      limitName: 'retry_admin_1h',
      message: 'Please wait before retrying this delivery.',
    });
  }

  if (input.providerId && input.context === 'retry') {
    windows.push({
      key: communicationCounterKey(`${input.channel}:retry:provider:${input.providerId}:1h`),
      ttlMs: 60 * 60 * 1000,
      limit: COMMUNICATION_MANUAL_RETRY_PROVIDER_HOURLY_LIMIT,
      limitName: 'retry_provider_1h',
      message: 'Please wait before retrying this delivery.',
    });
  }

  for (const window of windows) {
    if (!Number.isFinite(window.limit) || window.limit <= 0) continue;
    try {
      const allowed = await bumpWindow(redis, window.key, window.ttlMs, window.limit);
      if (!allowed) {
        await recordCommunicationBlock({
          ...input,
          limitName: window.limitName,
          reason: window.message,
          retryAfterMs: window.ttlMs,
        });
        return {
          allowed: false,
          code: 'COMMUNICATION_RATE_LIMITED',
          message: window.message,
          limitName: window.limitName,
          retryAfterMs: window.ttlMs,
        };
      }
    } catch (err) {
      logger.error({ error: err instanceof Error ? err.message : String(err) }, 'Communication abuse limit check failed, failing open');
      return { allowed: true };
    }
  }

  return { allowed: true };
}

async function applyBlock(req: Request, route: string, ip: string, identifier?: string, threat: ThreatKind = 'SUSPICIOUS_ACTIVITY_BLOCKED', ttlMs = DEFAULT_BLOCK_TTL_MS, scope: 'ip' | 'identifier' | 'both' = 'both') {
  const redis = getRedisClient();
  if (!redis) return;

  const multi = redis.multi();
  if (scope === 'ip' || scope === 'both') {
    multi.set(ipBlockKey(ip), route, 'PX', ttlMs);
  }
  if (identifier && (scope === 'identifier' || scope === 'both')) {
    multi.set(identifierBlockKey(identifier), route, 'PX', ttlMs);
  }
  await multi.exec();
  incrementMetric('rate_limit_block_total');
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
  if (useRelaxedDevAbuseRules(ip)) return;
  const key = riskKey(ip);
  try {
    const current = await redis.incr(key);
    if (current === 1) {
      await redis.pexpire(key, opts.ttlMs ?? DEFAULT_RISK_TTL_MS);
    }
    if (current >= (opts.blockAfter ?? 8)) {
      const scope = opts.identifier ? 'identifier' : 'both';
      await applyBlock(opts.req, opts.route, ip, opts.identifier, opts.threat ?? 'BOT_TRAFFIC_SPIKE', opts.blockTtlMs ?? DEFAULT_BLOCK_TTL_MS, scope);
    }
  } catch (err) {
    logger.error({ error: err instanceof Error ? err.message : String(err) }, 'noteRiskAndMaybeBlock redis error, failing open');
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
    logger.error({ error: err instanceof Error ? err.message : String(err) }, 'clearRisk redis error, ignoring');
  }
}

export async function clearLoginAbuseState(opts: { req: Request; identifier?: string }) {
  const redis = getRedisClient();
  if (!redis) return;
  try {
    const ip = getClientIp(opts.req);
    await redis.del(riskKey(ip));
    await redis.del(ipBlockKey(ip));
    if (opts.identifier) {
      await redis.del(identifierBlockKey(opts.identifier));
    }
  } catch (err) {
    logger.error({ error: err instanceof Error ? err.message : String(err) }, 'clearLoginAbuseState redis error, ignoring');
  }
}

export async function isTemporarilyBlocked(req: Request, identifier?: string): Promise<boolean> {
  const redis = getRedisClient();
  if (!redis) return false;
  const ip = getClientIp(req);
  if (useRelaxedDevAbuseRules(ip)) return false;
  try {
    if (await redis.exists(ipBlockKey(ip))) return true;
    if (identifier && await redis.exists(identifierBlockKey(identifier))) return true;
    return false;
  } catch (err) {
    logger.error({ error: err instanceof Error ? err.message : String(err) }, 'isTemporarilyBlocked redis error, failing open');
    return false;
  }
}

export function enterpriseRateLimit(opts: RateLimitOptions) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const redis = getRedisClient();
    const ip = getClientIp(req);
    const identifier = opts.identifierFrom?.(req)?.trim();
    if (useRelaxedDevAbuseRules(ip) && opts.route.startsWith('auth-')) {
      return next();
    }
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
      logger.error({ error: err instanceof Error ? err.message : String(err) }, 'Enterprise rate limit error');
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
