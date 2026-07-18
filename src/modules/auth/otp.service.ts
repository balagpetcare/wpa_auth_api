// Email/phone passwordless OTP login. Reuses the existing
// CommunicationProvider system (sendOtpEmail/sendOtpSms in
// modules/communication/communication.service.ts, which already handle
// provider routing/templates) and the existing antiAbuse.ts rate-limit
// primitives (checkCommunicationAbuseLimits) — no parallel rate limiter.
// Code storage/attempt-tracking uses Redis (same store already used by
// antiAbuse.ts), never the DB, and the raw code itself is never logged
// (only its sha256 hash, and only at debug level with the code redacted).
import { randomInt, createHash } from 'crypto';
import type { Request } from 'express';
import { UserStatus, type OtpTemplatePurpose } from '@prisma/client';
import { prisma } from '../../lib/db.js';
import { config } from '../../config/index.js';
import { getRedisClient } from '../../lib/redis.js';
import { AppError, ErrorCodes } from '../../lib/errors.js';
import { checkCommunicationAbuseLimits, getClientIp, hashAbuseValue } from '../../lib/antiAbuse.js';
import { sendOtpEmail, sendOtpSms } from '../communication/communication.service.js';
import { signAccessToken, signRefreshToken, hashToken, generateOpaqueToken, parseTtlToSeconds } from '../../lib/tokens.js';
import { writeAuditLog } from '../../lib/audit.js';
import { logger } from '../../lib/logger.js';
import { resolveClient, getOrCreateInternalClientId } from './auth.service.js';

export type OtpChannel = 'email' | 'phone' | 'whatsapp';

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function normalizePhone(phone: string) {
  return phone.trim();
}

function otpKey(channel: OtpChannel, recipient: string) {
  return `otp:login:${channel}:${hashAbuseValue(recipient)}`;
}

function cooldownKey(channel: OtpChannel, recipient: string) {
  return `otp:login:cooldown:${channel}:${hashAbuseValue(recipient)}`;
}

function hashCode(code: string) {
  return createHash('sha256').update(code).digest('hex');
}

function generateCode(): string {
  const length = config.OTP_LOGIN_CODE_LENGTH;
  const min = 10 ** (length - 1);
  const max = 10 ** length - 1;
  return String(randomInt(min, max + 1));
}

export async function requestLoginOtp(
  opts: { channel: OtpChannel; recipient: string; clientId?: string },
  req: Request,
) {
  const redis = getRedisClient();
  if (!redis) {
    throw new AppError('OTP delivery is temporarily unavailable.', 'SERVICE_UNAVAILABLE', 503);
  }

  if (opts.channel === 'whatsapp') {
    // No approved WhatsApp-capable CommunicationProvider exists in this
    // codebase today (CommunicationChannel enum only has SMS/EMAIL) — per
    // the hard rule, this returns PROVIDER_DISABLED rather than silently
    // falling back to SMS or faking delivery.
    throw new AppError('WhatsApp OTP delivery is not enabled.', ErrorCodes.PROVIDER_DISABLED, 503);
  }

  const recipient = opts.channel === 'email' ? normalizeEmail(opts.recipient) : normalizePhone(opts.recipient);
  const channelUpper = opts.channel === 'email' ? 'EMAIL' : 'SMS';

  // Resend cooldown (independent from, and in addition to, the general
  // communication abuse windows below).
  const cdKey = cooldownKey(opts.channel, recipient);
  const remainingCooldownMs = await redis.pttl(cdKey);
  if (remainingCooldownMs && remainingCooldownMs > 0) {
    throw new AppError(
      'Please wait before requesting another code.',
      'OTP_RESEND_COOLDOWN',
      429,
      { retryAfterSeconds: Math.ceil(remainingCooldownMs / 1000) },
    );
  }

  const decision = await checkCommunicationAbuseLimits({
    channel: channelUpper,
    purpose: 'LOGIN' as OtpTemplatePurpose,
    recipient,
    req,
    context: 'send',
  });
  if (!decision.allowed) {
    throw new AppError(decision.message, decision.code, 429);
  }

  // Anti-enumeration: we always report success even if no account exists
  // for this identifier — the same principle already used by
  // forgotPassword() in auth.service.ts.
  const user = opts.channel === 'email'
    ? await prisma.user.findFirst({ where: { email: recipient } })
    : await prisma.user.findFirst({ where: { phone: recipient } });

  const shouldActuallySend = Boolean(
    user
    && user.status !== UserStatus.DELETED
    && (opts.channel === 'email' ? user.emailVerifiedAt : user.phoneVerifiedAt),
  );

  if (shouldActuallySend) {
    const code = generateCode();
    const expirySeconds = config.OTP_LOGIN_EXPIRY_MINUTES * 60;
    const key = otpKey(opts.channel, recipient);
    await redis.set(
      key,
      JSON.stringify({ codeHash: hashCode(code), attempts: 0, userId: user!.id }),
      'EX',
      expirySeconds,
    );
    await redis.set(cdKey, '1', 'PX', config.OTP_LOGIN_RESEND_COOLDOWN_SECONDS * 1000);

    try {
      if (opts.channel === 'email') {
        await sendOtpEmail({ email: recipient, otp: code, purpose: 'LOGIN', minutes: config.OTP_LOGIN_EXPIRY_MINUTES, userId: user!.id, clientId: opts.clientId });
      } else {
        await sendOtpSms({ phone: recipient, otp: code, purpose: 'LOGIN', minutes: config.OTP_LOGIN_EXPIRY_MINUTES, userId: user!.id, clientId: opts.clientId });
      }
    } catch (err) {
      // Never log the raw code — only that a send attempt failed.
      logger.error({ error: err instanceof Error ? err.message : String(err), channel: opts.channel }, 'Failed to send login OTP');
    }
  } else {
    // Still burn the resend cooldown for a non-existent/unverified
    // recipient so a caller can't use response timing/cooldown presence to
    // distinguish "account exists" from "account doesn't exist".
    await redis.set(cdKey, '1', 'PX', config.OTP_LOGIN_RESEND_COOLDOWN_SECONDS * 1000);
  }

  return {
    success: true,
    message: 'If an account exists for that recipient, a verification code has been sent.',
    expiresInSeconds: config.OTP_LOGIN_EXPIRY_MINUTES * 60,
    resendCooldownSeconds: config.OTP_LOGIN_RESEND_COOLDOWN_SECONDS,
  };
}

export async function verifyLoginOtp(
  opts: { channel: Exclude<OtpChannel, 'whatsapp'>; recipient: string; code: string; clientId?: string },
  req: Request,
) {
  const redis = getRedisClient();
  if (!redis) {
    throw new AppError('OTP verification is temporarily unavailable.', 'SERVICE_UNAVAILABLE', 503);
  }
  const recipient = opts.channel === 'email' ? normalizeEmail(opts.recipient) : normalizePhone(opts.recipient);
  const key = otpKey(opts.channel, recipient);
  const raw = await redis.get(key);
  if (!raw) {
    throw new AppError('Code is invalid or has expired.', 'OTP_INVALID', 400);
  }
  const state = JSON.parse(raw) as { codeHash: string; attempts: number; userId: string };
  if (state.attempts >= config.OTP_LOGIN_MAX_VERIFY_ATTEMPTS) {
    await redis.del(key);
    throw new AppError('Too many incorrect attempts. Request a new code.', 'OTP_TOO_MANY_ATTEMPTS', 429);
  }
  if (state.codeHash !== hashCode(opts.code)) {
    state.attempts += 1;
    const ttl = await redis.pttl(key);
    await redis.set(key, JSON.stringify(state), 'PX', ttl > 0 ? ttl : 1000);
    throw new AppError('Code is invalid or has expired.', 'OTP_INVALID', 400);
  }

  await redis.del(key);

  const user = await prisma.user.findUnique({ where: { id: state.userId } });
  if (!user || user.status === UserStatus.DELETED || user.status === UserStatus.SUSPENDED) {
    throw new AppError('Account is not active.', 'ACCOUNT_INACTIVE', 403);
  }

  const client = await resolveClient(opts.clientId, req);
  const clientDbId = client?.id ?? (await getOrCreateInternalClientId());
  const audience = client?.audience ?? undefined;

  const roles = (await prisma.userRole.findMany({ where: { userId: user.id }, include: { role: true } })).map((r) => r.role.name);
  const session = await prisma.loginSession.create({
    data: {
      userId: user.id,
      clientId: clientDbId,
      sessionToken: generateOpaqueToken(),
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
    },
  });
  const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username, roles, sid: session.id }, audience);
  const refreshToken = signRefreshToken(user.id, audience);
  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId: clientDbId,
      tokenHash: hashToken(refreshToken),
      scopes: ['openid', 'offline_access'],
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      familyId: session.id,
    },
  });
  await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  await writeAuditLog({ userId: user.id, clientId: clientDbId, action: 'LOGIN', metadata: { method: 'otp', channel: opts.channel }, req });

  return {
    accessToken,
    refreshToken,
    expiresIn: parseTtlToSeconds(config.ACCESS_TOKEN_TTL),
    user: { id: user.id, email: user.email, phone: user.phone, displayName: user.displayName, roles },
  };
}
