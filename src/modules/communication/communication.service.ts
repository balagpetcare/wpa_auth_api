import {
  CommunicationChannel,
  CommunicationCredentialTestStatus,
  CommunicationDeliveryStatus,
  CommunicationHealthStatus,
  CommunicationPurpose,
  CommunicationProviderStatus,
  CommunicationProviderEnvironment,
  OtpTemplateLanguage,
  OtpTemplatePurpose,
  Prisma,
} from '@prisma/client';
import type { Request } from 'express';
import { prisma } from '../../lib/db.js';
import { AppError } from '../../lib/errors.js';
import { decryptCredentialPayload, encryptCredentialPayload, maskSecret } from '../../lib/credentialEncryption.js';
import { writeAuditLog } from '../../lib/audit.js';
import { createAdminNotification } from '../../lib/adminNotifications.js';
import { config } from '../../config/index.js';
import { logger } from '../../lib/logger.js';
import { resolveEmailAdapter, resolveSmsAdapter } from './communication.adapters.js';
import { getRedisClient } from '../../lib/redis.js';
import { enqueueCommunicationJob } from '../../lib/communicationQueue.js';
import { incrementMetric } from '../../lib/metrics.js';
import { decodeCursor, encodeCursor } from '../../lib/pagination.js';
import { ChannelDisabledError } from './communication.types.js';
import type {
  OtpCommunicationInput,
  ProviderCredentialSecrets,
  ProviderSendResult,
  RoutingSelectionInput,
} from './communication.types.js';

type ProviderWithCredential = Prisma.CommunicationProviderGetPayload<{
  include: { credentials: true };
}>;

const MAX_DELIVERY_ATTEMPTS = 3;

function normalizePhoneToE164(phone: string) {
  let cleaned = phone.replace(/[^\d+]/g, '');
  
  // Normalize BD local format (017... -> +88017...)
  if (!cleaned.startsWith('+') && cleaned.startsWith('01') && cleaned.length === 11) {
    cleaned = '+88' + cleaned;
  } else if (!cleaned.startsWith('+')) {
    cleaned = '+' + cleaned;
  }

  // Validate E.164 format
  if (!/^\+[1-9]\d{7,14}$/.test(cleaned)) {
    throw new AppError('Phone number must be in a valid E.164 format.', 'VALIDATION_ERROR', 400);
  }
  return cleaned;
}

function extractCountryCode(phone: string) {
  const normalized = normalizePhoneToE164(phone);
  const digits = normalized.slice(1);
  const candidates = ['880', '1', '44', '91', '61', '971'];
  return candidates.find((candidate) => digits.startsWith(candidate)) ?? digits.slice(0, 3);
}

function purposeToCommunicationPurpose(purpose: OtpTemplatePurpose): CommunicationPurpose {
  switch (purpose) {
    case 'PASSWORD_RESET':
      return 'PASSWORD_RESET';
    case 'LOGIN':
    case 'REGISTER':
      return 'AUTH';
    default:
      return 'OTP';
  }
}

function mapProvider(provider: ProviderWithCredential) {
  const activeCredential = provider.credentials.find((credential) => credential.isActive);
  return {
    ...provider,
    activeCredential,
  };
}

function getCredentialSecrets(provider: ProviderWithCredential) {
  const credential = provider.credentials.find((item) => item.isActive);
  if (!credential) throw new AppError('Provider has no active credentials.', 'BAD_REQUEST', 400);
  return decryptCredentialPayload(credential.encryptedSecrets as any) as ProviderCredentialSecrets;
}

function getMaskedPreview(secrets: Record<string, string>) {
  return Object.fromEntries(
    Object.entries(secrets).map(([key, value]) => [key, /password/i.test(key) ? '********' : maskSecret(value)]),
  );
}

async function writeProviderAuditLog(input: {
  actorAdminId?: string | null;
  providerId?: string | null;
  action: string;
  metadata?: Prisma.InputJsonValue;
  req?: Request;
}) {
  await prisma.communicationProviderAuditLog.create({
    data: {
      actorAdminId: input.actorAdminId ?? null,
      providerId: input.providerId ?? null,
      action: input.action,
      metadata: input.metadata,
      ipAddress: input.req ? (input.req.ip ?? input.req.socket.remoteAddress) : undefined,
      userAgent: input.req?.headers['user-agent'],
    },
  });
}

async function updateProviderHealth(providerId: string, result: ProviderSendResult) {
  if (result.success) {
    await prisma.communicationProvider.update({
      where: { id: providerId },
      data: {
        successCount: { increment: 1 },
        lastSuccessAt: new Date(),
        healthStatus: 'HEALTHY',
        lastFailureMessage: null,
      },
    });
    return;
  }

  const provider = await prisma.communicationProvider.update({
    where: { id: providerId },
    data: {
      failureCount: { increment: 1 },
      lastFailureAt: new Date(),
      lastFailureMessage: result.errorMessage,
    },
  });

  const nextHealth: CommunicationHealthStatus = provider.failureCount + 1 >= 5 ? 'DOWN' : 'DEGRADED';
  await prisma.communicationProvider.update({
    where: { id: providerId },
    data: { healthStatus: nextHealth },
  });

  if (nextHealth === 'DOWN') {
    await createAdminNotification({
      type: 'COMMUNICATION_PROVIDER_DOWN',
      title: 'Communication provider down',
      message: `${provider.name} is marked down after repeated failures.`,
      severity: 'ERROR',
      category: 'SYSTEM',
      actionUrl: '/communication/provider-health',
    });
  }
}

async function logDeliveryAttempt(input: {
  channel: CommunicationChannel;
  purpose: OtpTemplatePurpose;
  recipient: string;
  countryCode?: string | null;
  providerId?: string | null;
  templateId?: string | null;
  attemptNo: number;
  result: ProviderSendResult;
}) {
  await prisma.communicationDeliveryLog.create({
    data: {
      channel: input.channel,
      purpose: input.purpose,
      recipient: input.recipient,
      countryCode: input.countryCode ?? null,
      providerId: input.providerId ?? null,
      templateId: input.templateId ?? null,
      status: input.result.success ? 'SENT' : input.attemptNo > 1 ? 'RETRIED' : 'FAILED',
      attemptNo: input.attemptNo,
      providerResponse: (input.result.rawResponse as Prisma.InputJsonValue | undefined) ?? undefined,
      errorCode: input.result.errorCode,
      errorMessage: input.result.errorMessage,
      sentAt: input.result.success ? new Date() : null,
      failedAt: input.result.success ? null : new Date(),
    },
  });
}

export async function deliverQueuedEmail(input: {
  to: string;
  subject: string;
  text: string;
  html?: string;
  purpose: OtpTemplatePurpose;
  clientId?: string | null;
  senderName?: string | null;
  senderEmail?: string | null;
  replyTo?: string | null;
  environment?: 'SANDBOX' | 'LIVE' | null;
}) {
  const communicationPurpose = purposeToCommunicationPurpose(input.purpose);
  let providers;
  try {
    providers = await findCandidateProviders({
      channel: 'EMAIL',
      purpose: communicationPurpose,
      appId: input.clientId,
      environment: input.environment,
    });
  } catch (err) {
    if (err instanceof ChannelDisabledError) {
      await logChannelDisabledBlock({
        ruleId: err.ruleId,
        channel: 'EMAIL',
        purpose: input.purpose,
        recipient: input.to,
        appId: input.clientId,
      });
      throw new AppError('Email is disabled for this application.', 'CHANNEL_DISABLED', 403);
    }
    throw err;
  }
  if (!providers.length) {
    throw new AppError('Email delivery is temporarily unavailable.', 'COMMUNICATION_UNAVAILABLE', 503);
  }

  const attemptsLimit = Math.min(providers.length, MAX_DELIVERY_ATTEMPTS);
  let rateLimitedCount = 0;
  for (let index = 0; index < attemptsLimit; index += 1) {
    const provider = providers[index];
    const limitCheck = await checkProviderRateLimit(provider);
    if (!limitCheck.allowed) {
      rateLimitedCount += 1;
      await logRateLimitBlock(provider, input.to, limitCheck.reason!);
      continue;
    }

    const credentials = getCredentialSecrets(provider);
    const adapter = resolveEmailAdapter(provider.code);
    const result = await adapter.sendEmail({
      to: input.to,
      subject: input.subject,
      text: input.text,
      html: input.html,
      provider,
      credentials,
      config: {
        fromEmail: input.senderEmail ?? provider.activeCredential?.fromEmail ?? null,
        fromName: input.senderName ?? provider.activeCredential?.fromName ?? null,
        replyTo: input.replyTo ?? null,
        smtpHost: provider.activeCredential?.smtpHost ?? null,
        smtpPort: provider.activeCredential?.smtpPort ?? null,
        smtpSecure: provider.activeCredential?.smtpSecure ?? null,
      },
    });

    await logDeliveryAttempt({
      channel: 'EMAIL',
      purpose: input.purpose,
      recipient: input.to,
      providerId: provider.id,
      attemptNo: index + 1,
      result,
    });
    await updateProviderHealth(provider.id, result);
    if (result.success) {
      incrementMetric('email_send_total');
      return result;
    }
  }

  if (rateLimitedCount > 0 && rateLimitedCount === attemptsLimit) {
    throw new AppError('Email delivery is temporarily rate-limited. Please try again shortly.', 'COMMUNICATION_RATE_LIMITED', 429);
  }

  await createAdminNotification({
    type: 'EMAIL_DELIVERY_FAILED',
    title: 'Email OTP delivery failed',
    message: `All active email providers failed while sending to ${input.to}.`,
    severity: 'ERROR',
    category: 'SYSTEM',
    actionUrl: '/communication/provider-health',
  });
  incrementMetric('email_failure_total');
  throw new AppError('Unable to send email at this time.', 'COMMUNICATION_UNAVAILABLE', 503);
}

export async function deliverQueuedSms(input: {
  to: string;
  message: string;
  purpose: OtpTemplatePurpose;
  clientId?: string | null;
  environment?: 'SANDBOX' | 'LIVE' | null;
}) {
  const countryCode = extractCountryCode(input.to);
  const communicationPurpose = purposeToCommunicationPurpose(input.purpose);
  let providers;
  try {
    providers = await findCandidateProviders({
      channel: 'SMS',
      purpose: communicationPurpose,
      countryCode,
      appId: input.clientId,
      environment: input.environment,
    });
  } catch (err) {
    if (err instanceof ChannelDisabledError) {
      await logChannelDisabledBlock({
        ruleId: err.ruleId,
        channel: 'SMS',
        purpose: input.purpose,
        recipient: input.to,
        appId: input.clientId,
        countryCode,
      });
      throw new AppError('SMS is disabled for this application/country.', 'CHANNEL_DISABLED', 403);
    }
    throw err;
  }
  if (!providers.length) {
    throw new AppError('SMS delivery is temporarily unavailable.', 'COMMUNICATION_UNAVAILABLE', 503);
  }

  const attemptsLimit = Math.min(providers.length, MAX_DELIVERY_ATTEMPTS);
  let rateLimitedCount = 0;
  for (let index = 0; index < attemptsLimit; index += 1) {
    const provider = providers[index];
    const limitCheck = await checkProviderRateLimit(provider);
    if (!limitCheck.allowed) {
      rateLimitedCount += 1;
      await logRateLimitBlock(provider, input.to, limitCheck.reason!);
      continue;
    }

    const credentials = getCredentialSecrets(provider);
    const adapter = resolveSmsAdapter(provider.code);
    const result = await adapter.sendSms({
      to: normalizePhoneToE164(input.to),
      message: input.message,
      countryCode,
      provider,
      credentials,
    });

    await logDeliveryAttempt({
      channel: 'SMS',
      purpose: input.purpose,
      recipient: input.to,
      countryCode,
      providerId: provider.id,
      attemptNo: index + 1,
      result,
    });
    await updateProviderHealth(provider.id, result);
    if (result.success) {
      incrementMetric('sms_send_total');
      return result;
    }
  }

  if (rateLimitedCount > 0 && rateLimitedCount === attemptsLimit) {
    throw new AppError('SMS delivery is temporarily rate-limited. Please try again shortly.', 'COMMUNICATION_RATE_LIMITED', 429);
  }

  await createAdminNotification({
    type: 'SMS_DELIVERY_FAILED',
    title: 'SMS OTP delivery failed',
    message: `All active SMS providers failed while sending to ${input.to}.`,
    severity: 'ERROR',
    category: 'SYSTEM',
    actionUrl: '/communication/provider-health',
  });
  incrementMetric('sms_failure_total');
  throw new AppError('Unable to send SMS at this time.', 'COMMUNICATION_UNAVAILABLE', 503);
}

// Phase 2.6A (docs/phase-2-6a-app-aware-communication-routing-ui.md):
// resolves the single most-specific active routing rule for a given
// app/country/channel/purpose scope. Precedence (most specific wins):
//   1. appId exact match + countryCode exact match
//   2. appId exact match + countryCode null (app's own global default)
//   3. appId null      + countryCode exact match (system-wide country default)
//   4. appId null      + countryCode null (system-wide default)
// Rules with an `environment` set are only eligible when it matches the
// caller's environment (or the caller didn't specify one). Mirrors the
// nullable-override precedence pattern already used by EmailTemplate.clientId.
function resolveMostSpecificRule<
  T extends { appId: string | null; countryCode: string | null; environment: string | null; priority: number; createdAt: Date },
>(rules: T[], input: RoutingSelectionInput): T | null {
  const envCompatible = rules.filter((r) => !r.environment || !input.environment || r.environment === input.environment);

  const tiers: Array<(r: T) => boolean> = [
    (r) => !!input.appId && r.appId === input.appId && !!input.countryCode && r.countryCode === input.countryCode,
    (r) => !!input.appId && r.appId === input.appId && r.countryCode === null,
    (r) => r.appId === null && !!input.countryCode && r.countryCode === input.countryCode,
    (r) => r.appId === null && r.countryCode === null,
  ];

  for (const matchesTier of tiers) {
    const tierMatches = envCompatible.filter(matchesTier);
    if (tierMatches.length > 0) {
      // Within a tier, lowest priority number wins (existing convention),
      // tie-broken by oldest rule first — same ordering already used
      // elsewhere in this file.
      return tierMatches.sort((a, b) => a.priority - b.priority || a.createdAt.getTime() - b.createdAt.getTime())[0];
    }
  }
  return null;
}

async function findCandidateProviders(input: RoutingSelectionInput) {
  const rules = await prisma.communicationRoutingRule.findMany({
    where: {
      channel: input.channel,
      purpose: input.purpose,
      isActive: true,
      // Broad DB-side filter (any rule that could conceivably apply to
      // this app or globally, this country or globally) — the precedence
      // logic above narrows it down to exactly one rule in application code.
      appId: input.appId ? undefined : null,
      ...(input.appId ? { OR: [{ appId: input.appId }, { appId: null }] } : {}),
      AND: [
        {
          OR: [{ countryCode: input.countryCode ?? null }, { countryCode: null }],
        },
      ],
    },
    orderBy: [{ priority: 'asc' }, { createdAt: 'asc' }],
  });

  const selectedRule = resolveMostSpecificRule(rules, input);

  if (selectedRule && !selectedRule.enabled) {
    // Hard kill-switch: the most specific matching rule explicitly disables
    // this channel for this scope. No fallback is attempted — the caller
    // (dispatchEmail/dispatchSms) is responsible for catching this,
    // auditing the block, and returning a clean CHANNEL_DISABLED error.
    throw new ChannelDisabledError(selectedRule.id);
  }

  const routedProviderIds = selectedRule
    ? [selectedRule.providerId, ...(Array.isArray(selectedRule.fallbackProviderIds) ? (selectedRule.fallbackProviderIds as string[]) : [])].filter(
        (id): id is string => !!id,
      )
    : [];

  // fallbackEnabled=false on the selected rule means: only the rule's own
  // explicit provider + fallback chain may be tried — do not fall through
  // to the general eligible-provider pool or the international-fallback tier.
  const restrictToExplicitChain = !!selectedRule && !selectedRule.fallbackEnabled && routedProviderIds.length > 0;

  const where: Prisma.CommunicationProviderWhereInput = restrictToExplicitChain
    ? { deletedAt: null, id: { in: routedProviderIds } }
    : {
        deletedAt: null,
        type: input.channel,
        status: { in: ['ACTIVE', 'TESTING'] },
        healthStatus: { not: 'DOWN' },
        supportedPurposes: { has: input.purpose },
        ...(input.environment ? { environment: input.environment } : {}),
      };

  if (!restrictToExplicitChain && input.channel === 'SMS') {
    where.OR = [{ countryCode: input.countryCode ?? undefined }, { isGlobal: true }];
  }

  const providers = await prisma.communicationProvider.findMany({
    where,
    include: { credentials: true },
    orderBy: [{ priority: 'asc' }, { createdAt: 'asc' }],
  });

  const ranked = providers
    .map(mapProvider)
    .filter((provider) => provider.activeCredential)
    .sort((a, b) => {
      const aRouted = routedProviderIds.includes(a.id) ? 0 : 1;
      const bRouted = routedProviderIds.includes(b.id) ? 0 : 1;
      if (aRouted !== bRouted) return aRouted - bRouted;
      if (input.channel === 'SMS') {
        const aCountry = a.countryCode === input.countryCode ? 0 : a.isGlobal ? 1 : 2;
        const bCountry = b.countryCode === input.countryCode ? 0 : b.isGlobal ? 1 : 2;
        if (aCountry !== bCountry) return aCountry - bCountry;
      }
      return a.priority - b.priority;
    });

  return ranked;
}

function renderTemplate(body: string, variables: Record<string, string>) {
  return Object.entries(variables).reduce(
    (acc, [key, value]) => acc.replaceAll(`{{${key}}}`, value),
    body,
  );
}

async function resolveOtpTemplate(channel: CommunicationChannel, purpose: OtpTemplatePurpose, language: OtpTemplateLanguage) {
  const exact = await prisma.otpTemplate.findFirst({
    where: { channel, purpose, language, isActive: true },
    orderBy: [{ isDefault: 'desc' }, { createdAt: 'asc' }],
  });
  if (exact) return exact;
  return prisma.otpTemplate.findFirst({
    where: { channel, purpose: 'GENERAL', language, isActive: true },
    orderBy: [{ isDefault: 'desc' }, { createdAt: 'asc' }],
  });
}

// Phase 2 module (docs/phase-2-core-identity-admin-modules.md): the
// CommunicationProvider model already had rateLimitPerMinute/dailyLimit/
// monthlyLimit fields (editable via the admin UI), but nothing enforced
// them at send time — a misconfigured or compromised OTP flow could hammer
// a provider (and rack up real SMS/email costs) with no backend guard.
//
// Enforcement uses Redis INCR+EXPIRE counters keyed per provider per
// window, mirroring the pattern in middleware/rateLimit.ts. If Redis is
// unavailable, this fails OPEN (does not block sends) rather than taking
// down OTP/password-reset/email-verification for a rate-limiting outage —
// the primary auth rate limiters (loginRateLimit etc.) already fail closed
// in production for the security-critical login path; this is a cost/abuse
// guard for outbound provider traffic, not an auth boundary, so
// availability is prioritized here.
async function checkProviderRateLimit(provider: { id: string; rateLimitPerMinute: number | null; dailyLimit: number | null; monthlyLimit: number | null }): Promise<{ allowed: boolean; reason?: string }> {
  const redisClient = getRedisClient();
  if (!redisClient) return { allowed: true };

  const now = new Date();
  const windows: Array<{ key: string; ttlSeconds: number; limit: number | null; reason: string }> = [
    {
      key: `comm-limit:${provider.id}:minute:${Math.floor(now.getTime() / 60000)}`,
      ttlSeconds: 60,
      limit: provider.rateLimitPerMinute,
      reason: 'rateLimitPerMinute',
    },
    {
      key: `comm-limit:${provider.id}:day:${now.toISOString().slice(0, 10)}`,
      ttlSeconds: 24 * 60 * 60,
      limit: provider.dailyLimit,
      reason: 'dailyLimit',
    },
    {
      key: `comm-limit:${provider.id}:month:${now.toISOString().slice(0, 7)}`,
      ttlSeconds: 31 * 24 * 60 * 60,
      limit: provider.monthlyLimit,
      reason: 'monthlyLimit',
    },
  ];

  for (const window of windows) {
    if (window.limit === null || window.limit === undefined) continue;
    try {
      const current = await redisClient.incr(window.key);
      if (current === 1) {
        await redisClient.expire(window.key, window.ttlSeconds);
      }
      if (current > window.limit) {
        return { allowed: false, reason: window.reason };
      }
    } catch (err) {
      console.error('Communication rate limit check failed, failing open:', err);
      return { allowed: true };
    }
  }

  return { allowed: true };
}

async function logRateLimitBlock(provider: { id: string }, recipient: string, reason: string) {
  try {
    await writeProviderAuditLog({
      providerId: provider.id,
      action: 'COMMUNICATION_RATE_LIMIT_BLOCKED',
      metadata: { recipient, reason },
    });
  } catch (err) {
    console.error('Failed to write rate-limit-blocked audit log:', err);
  }
}

// Phase 2.6A (docs/phase-2-6a-app-aware-communication-routing-ui.md):
// audit trail for a hard channel-disable block, so an admin can see exactly
// when/why a send attempt was refused, distinct from a delivery failure.
async function logChannelDisabledBlock(input: {
  ruleId: string;
  channel: CommunicationChannel;
  purpose: OtpTemplatePurpose;
  recipient: string;
  appId?: string | null;
  countryCode?: string | null;
}) {
  try {
    await writeProviderAuditLog({
      action: 'COMMUNICATION_CHANNEL_DISABLED_BLOCKED',
      metadata: {
        ruleId: input.ruleId,
        channel: input.channel,
        purpose: input.purpose,
        recipient: input.recipient,
        appId: input.appId ?? null,
        countryCode: input.countryCode ?? null,
      },
    });
  } catch (err) {
    console.error('Failed to write channel-disabled audit log:', err);
  }
}

export async function dispatchEmail(input: {
  to: string;
  subject: string;
  text: string;
  html?: string;
  purpose: OtpTemplatePurpose;
  clientId?: string | null;
  senderName?: string | null;
  senderEmail?: string | null;
  replyTo?: string | null;
  // Phase 2.6A: optional provider environment restriction (SANDBOX/LIVE).
  // Omitted by existing callers, who keep their prior behavior unchanged.
  environment?: 'SANDBOX' | 'LIVE' | null;
}) {
  const result = await enqueueCommunicationJob({
    type: 'send_email',
    payload: {
      subject: input.subject,
      text: input.text,
      html: input.html,
      recipientEmail: input.to,
      recipientName: input.senderName ?? undefined,
      clientId: input.clientId ?? null,
      locale: 'en',
      purpose: input.purpose,
      userId: null,
    },
  });
  if (result.queued) {
    incrementMetric('otp_send_total');
    return {
      success: true,
      queued: true,
      jobId: result.jobId,
    };
  }

  logger.warn({ reason: result.reason, recipient: input.to }, 'Queue unavailable, sending email synchronously');
  const direct = await deliverQueuedEmail({
    to: input.to,
    subject: input.subject,
    text: input.text,
    html: input.html,
    purpose: input.purpose,
    clientId: input.clientId ?? null,
    senderName: input.senderName ?? null,
    senderEmail: input.senderEmail ?? null,
    replyTo: input.replyTo ?? null,
    environment: input.environment ?? null,
  });
  return { success: direct.success, queued: false, jobId: null };
}

export async function dispatchSms(input: {
  to: string;
  message: string;
  purpose: OtpTemplatePurpose;
  // Phase 2.6A: app scope + optional environment restriction, same
  // backward-compatible pattern as dispatchEmail above.
  clientId?: string | null;
  environment?: 'SANDBOX' | 'LIVE' | null;
}) {
  const result = await enqueueCommunicationJob({
    type: 'send_sms',
    payload: {
      to: input.to,
      message: input.message,
      purpose: input.purpose,
      clientId: input.clientId ?? null,
      userId: null,
    },
  });
  if (result.queued) {
    incrementMetric('otp_send_total');
    return {
      success: true,
      queued: true,
      jobId: result.jobId,
    };
  }

  logger.warn({ reason: result.reason, recipient: input.to }, 'Queue unavailable, sending SMS synchronously');
  const direct = await deliverQueuedSms({
    to: input.to,
    message: input.message,
    purpose: input.purpose,
    clientId: input.clientId ?? null,
    environment: input.environment ?? null,
  });
  return { success: direct.success, queued: false, jobId: null };
}

export async function sendOtpEmail(input: OtpCommunicationInput & { email: string }) {
  const language = input.language ?? 'EN';
  const template = await resolveOtpTemplate('EMAIL', input.purpose, language);
  if (!template) throw new AppError('Email OTP template is not configured.', 'COMMUNICATION_UNAVAILABLE', 503);
  const variables = {
    otp: input.otp,
    minutes: String(input.minutes ?? config.OTP_EXPIRY_MINUTES),
    appName: config.OTP_APP_NAME,
    purpose: input.purpose,
    supportEmail: config.OTP_SUPPORT_EMAIL,
  };
  const subject = template.subject || 'Your WPA verification code';
  const body = renderTemplate(template.body, variables);
  return dispatchEmail({
    to: input.email,
    subject,
    text: body.replace(/<[^>]+>/g, ''),
    html: body.replace(/\n/g, '<br />'),
    purpose: input.purpose,
    clientId: input.clientId,
  });
}

export async function sendOtpSms(input: OtpCommunicationInput & { phone: string }) {
  const language = input.language ?? 'EN';
  const template = await resolveOtpTemplate('SMS', input.purpose, language);
  if (!template) throw new AppError('SMS OTP template is not configured.', 'COMMUNICATION_UNAVAILABLE', 503);
  const message = renderTemplate(template.body, {
    otp: input.otp,
    minutes: String(input.minutes ?? config.OTP_EXPIRY_MINUTES),
    appName: config.OTP_APP_NAME,
    purpose: input.purpose,
    supportEmail: config.OTP_SUPPORT_EMAIL,
  });
  return dispatchSms({ to: input.phone, message, purpose: input.purpose, clientId: input.clientId });
}

export async function sendOtpMultiChannel(input: OtpCommunicationInput) {
  const tasks: Promise<unknown>[] = [];
  if (input.email) tasks.push(sendOtpEmail({ ...input, email: input.email }));
  if (input.phone) tasks.push(sendOtpSms({ ...input, phone: input.phone }));
  return Promise.all(tasks);
}

export async function createOrUpdateProvider(input: {
  actorId: string;
  req: Request;
  providerId?: string;
  data: {
    name: string;
    code: string;
    type: CommunicationChannel;
    status?: CommunicationProviderStatus;
    environment?: 'SANDBOX' | 'LIVE';
    isGlobal?: boolean;
    countryCode?: string | null;
    priority?: number;
    supportedPurposes: CommunicationPurpose[];
    dailyLimit?: number | null;
    monthlyLimit?: number | null;
    rateLimitPerMinute?: number | null;
  };
}) {
  if (input.data.countryCode && !/^\d{1,4}$/.test(input.data.countryCode)) {
    throw new AppError('countryCode must be a dialing code value.', 'VALIDATION_ERROR', 400);
  }

  const payload = {
    ...input.data,
    code: input.data.code.toUpperCase(),
    updatedById: input.actorId,
  };

  const provider = input.providerId
    ? await prisma.communicationProvider.update({
        where: { id: input.providerId },
        data: payload,
      })
    : await prisma.communicationProvider.create({
        data: { ...payload, createdById: input.actorId },
      });

  await writeProviderAuditLog({
    actorAdminId: input.actorId,
    providerId: provider.id,
    action: input.providerId ? 'COMMUNICATION_PROVIDER_UPDATED' : 'COMMUNICATION_PROVIDER_CREATED',
    metadata: { type: provider.type, code: provider.code },
    req: input.req,
  });
  await writeAuditLog({
    userId: input.actorId,
    action: 'CLIENT_UPDATED',
    resource: 'communication_provider',
    resourceId: provider.id,
    metadata: { type: provider.type, code: provider.code },
    req: input.req,
  });
  return provider;
}

export async function softDeleteProvider(providerId: string, actorId: string, req: Request) {
  const activeRule = await prisma.communicationRoutingRule.findFirst({
    where: { providerId, isActive: true },
  });
  if (activeRule) {
    throw new AppError('Provider is used by an active routing rule.', 'BAD_REQUEST', 400);
  }
  const provider = await prisma.communicationProvider.update({
    where: { id: providerId },
    data: { deletedAt: new Date(), status: 'DISABLED', updatedById: actorId },
  });
  await writeProviderAuditLog({
    actorAdminId: actorId,
    providerId,
    action: 'COMMUNICATION_PROVIDER_DELETED',
    req,
  });
  return provider;
}

export async function upsertProviderCredential(input: {
  providerId: string;
  actorId: string;
  req: Request;
  credentialId?: string;
  data: {
    secrets: Record<string, string>;
    apiBaseUrl?: string | null;
    senderId?: string | null;
    fromName?: string | null;
    fromEmail?: string | null;
    smtpHost?: string | null;
    smtpPort?: number | null;
    smtpSecure?: boolean | null;
    isActive?: boolean;
  };
}) {
  if (!Object.keys(input.data.secrets ?? {}).length) {
    throw new AppError('Credential secrets are required.', 'VALIDATION_ERROR', 400);
  }

  const encryptedSecrets = encryptCredentialPayload(input.data.secrets);
  const maskedSecretsPreview = getMaskedPreview(input.data.secrets);
  const usernamePreview = input.data.secrets['username'] ? maskSecret(input.data.secrets['username']) : null;

  const shouldBeActive = input.data.isActive ?? true;
  const record = await prisma.$transaction(async (tx) => {
    if (shouldBeActive) {
      await tx.communicationProviderCredential.updateMany({
        where: { providerId: input.providerId, isActive: true },
        data: { isActive: false },
      });
    }

    return input.credentialId
      ? tx.communicationProviderCredential.update({
          where: { id: input.credentialId },
          data: {
            encryptedSecrets,
            maskedSecretsPreview,
            apiBaseUrl: input.data.apiBaseUrl,
            senderId: input.data.senderId,
            fromName: input.data.fromName,
            fromEmail: input.data.fromEmail,
            smtpHost: input.data.smtpHost,
            smtpPort: input.data.smtpPort,
            smtpSecure: input.data.smtpSecure,
            usernamePreview,
            isActive: shouldBeActive,
          },
        })
      : tx.communicationProviderCredential.create({
          data: {
            providerId: input.providerId,
            encryptedSecrets,
            maskedSecretsPreview,
            apiBaseUrl: input.data.apiBaseUrl,
            senderId: input.data.senderId,
            fromName: input.data.fromName,
            fromEmail: input.data.fromEmail,
            smtpHost: input.data.smtpHost,
            smtpPort: input.data.smtpPort,
            smtpSecure: input.data.smtpSecure,
            usernamePreview,
            isActive: shouldBeActive,
          },
        });
  });

  await writeProviderAuditLog({
    actorAdminId: input.actorId,
    providerId: input.providerId,
    action: input.credentialId ? 'COMMUNICATION_PROVIDER_CREDENTIAL_UPDATED' : 'COMMUNICATION_PROVIDER_CREDENTIAL_CREATED',
    req: input.req,
  });
  return {
    ...record,
    encryptedSecrets: undefined,
  };
}

export async function listProviders(filters?: { type?: CommunicationChannel }) {
  const providers = await prisma.communicationProvider.findMany({
    where: {
      deletedAt: null,
      ...(filters?.type ? { type: filters.type } : {}),
    },
    include: {
      credentials: {
        where: { isActive: true },
        orderBy: { updatedAt: 'desc' },
        take: 1,
      },
    },
    orderBy: [{ priority: 'asc' }, { createdAt: 'asc' }],
  });
  return providers.map((provider) => ({
    ...provider,
    credentials: provider.credentials.map((credential) => ({
      ...credential,
      encryptedSecrets: undefined,
    })),
  }));
}

export async function getProviderById(providerId: string) {
  const provider = await prisma.communicationProvider.findFirst({
    where: { id: providerId, deletedAt: null },
    include: { credentials: true },
  });
  if (!provider) throw new AppError('Provider not found.', 'NOT_FOUND', 404);
  return provider;
}

export async function setProviderStatus(providerId: string, status: CommunicationProviderStatus, actorId: string, req: Request) {
  const provider = await prisma.communicationProvider.findUnique({
    where: { id: providerId },
    include: { credentials: { where: { isActive: true } } },
  });
  if (!provider) throw new AppError('Provider not found.', 'NOT_FOUND', 404);
  if (status === 'ACTIVE' && provider.credentials.length === 0) {
    throw new AppError('Provider cannot be activated without an active credential.', 'BAD_REQUEST', 400);
  }
  const updated = await prisma.communicationProvider.update({
    where: { id: providerId },
    data: { status, updatedById: actorId },
  });
  await writeProviderAuditLog({
    actorAdminId: actorId,
    providerId,
    action: status === 'ACTIVE' ? 'COMMUNICATION_PROVIDER_ACTIVATED' : 'COMMUNICATION_PROVIDER_DEACTIVATED',
    req,
  });
  return updated;
}

export async function upsertRoutingRule(input: {
  actorId: string;
  req: Request;
  ruleId?: string;
  data: {
    // Phase 2.6A: nullable app scope — null/omitted keeps the existing
    // system-default-rule behavior exactly as before this change.
    appId?: string | null;
    channel: CommunicationChannel;
    countryCode?: string | null;
    purpose: CommunicationPurpose;
    language?: OtpTemplateLanguage | null;
    providerId?: string | null;
    fallbackProviderIds?: string[] | null;
    priority?: number;
    enabled?: boolean;
    fallbackEnabled?: boolean;
    environment?: CommunicationProviderEnvironment | null;
    isActive?: boolean;
  };
}) {
  const payload = {
    ...input.data,
    fallbackProviderIds: input.data.fallbackProviderIds ?? [],
  };
  const rule = input.ruleId
    ? await prisma.communicationRoutingRule.update({ where: { id: input.ruleId }, data: payload })
    : await prisma.communicationRoutingRule.create({ data: payload });
  await writeProviderAuditLog({
    actorAdminId: input.actorId,
    providerId: rule.providerId,
    action: input.ruleId ? 'COMMUNICATION_ROUTING_RULE_UPDATED' : 'COMMUNICATION_ROUTING_RULE_CREATED',
    req: input.req,
  });
  return rule;
}

export async function upsertOtpTemplate(input: {
  actorId: string;
  req: Request;
  templateId?: string;
  data: {
    channel: CommunicationChannel;
    purpose: OtpTemplatePurpose;
    language: OtpTemplateLanguage;
    subject?: string | null;
    body: string;
    variables?: string[] | null;
    isDefault?: boolean;
    isActive?: boolean;
  };
}) {
  const payload = {
    channel: input.data.channel,
    purpose: input.data.purpose,
    language: input.data.language,
    subject: input.data.subject ?? null,
    body: input.data.body,
    variables: input.data.variables ?? [],
    isDefault: input.data.isDefault ?? false,
    isActive: input.data.isActive ?? true,
  };
  const template = input.templateId
    ? await prisma.otpTemplate.update({ where: { id: input.templateId }, data: payload })
    : await prisma.otpTemplate.create({ data: payload });
  await writeProviderAuditLog({
    actorAdminId: input.actorId,
    action: input.templateId ? 'OTP_TEMPLATE_UPDATED' : 'OTP_TEMPLATE_CREATED',
    req: input.req,
    metadata: { templateId: template.id },
  });
  return template;
}

export async function testProvider(providerId: string, actorId: string, req: Request, input: { to: string; subject?: string; message?: string }) {
  const provider = await prisma.communicationProvider.findUnique({
    where: { id: providerId },
    include: { credentials: { where: { isActive: true } } },
  });
  if (!provider) throw new AppError('Provider not found.', 'NOT_FOUND', 404);
  const credential = provider.credentials[0];
  if (!credential) throw new AppError('Provider has no active credentials.', 'BAD_REQUEST', 400);
  const secrets = decryptCredentialPayload(credential.encryptedSecrets as any) as ProviderCredentialSecrets;

  let result: ProviderSendResult;
  if (provider.type === 'SMS') {
    result = await resolveSmsAdapter(provider.code).sendSms({
      to: input.to,
      message: input.message || 'WPA Central Auth test message',
      provider,
      credentials: secrets,
    });
  } else {
    result = await resolveEmailAdapter(provider.code).sendEmail({
      to: input.to,
      subject: input.subject || 'WPA Central Auth test email',
      text: input.message || 'This is a WPA Central Auth provider test.',
      html: `<p>${input.message || 'This is a WPA Central Auth provider test.'}</p>`,
      provider,
      credentials: secrets,
      config: {
        fromEmail: credential.fromEmail,
        fromName: credential.fromName,
        smtpHost: credential.smtpHost,
        smtpPort: credential.smtpPort,
        smtpSecure: credential.smtpSecure,
      },
    });
  }

  await prisma.communicationProviderCredential.update({
    where: { id: credential.id },
    data: {
      lastTestStatus: result.success ? 'PASSED' : 'FAILED',
      lastTestedAt: new Date(),
      lastTestMessage: result.success ? 'Provider test passed.' : result.errorMessage,
      lastTestDetails: (result.rawResponse as Prisma.InputJsonValue | undefined) ?? undefined,
    },
  });
  await writeProviderAuditLog({
    actorAdminId: actorId,
    providerId,
    action: provider.type === 'SMS' ? 'COMMUNICATION_PROVIDER_TEST_SMS' : 'COMMUNICATION_PROVIDER_TEST_EMAIL',
    metadata: { recipient: input.to, success: result.success },
    req,
  });
  await updateProviderHealth(providerId, result);
  incrementMetric('provider_health_check_total');
  return result;
}

export async function getProviderHealth() {
  return prisma.communicationProvider.findMany({
    where: { deletedAt: null },
    select: {
      id: true,
      name: true,
      code: true,
      type: true,
      status: true,
      healthStatus: true,
      successCount: true,
      failureCount: true,
      lastSuccessAt: true,
      lastFailureAt: true,
      lastFailureMessage: true,
      credentials: {
        where: { isActive: true },
        take: 1,
        select: {
          lastTestStatus: true,
          lastTestedAt: true,
          lastTestMessage: true,
        },
      },
    },
    orderBy: [{ type: 'asc' }, { priority: 'asc' }],
  });
}

export async function getDeliveryLogs(filters: {
  channel?: CommunicationChannel;
  providerId?: string;
  status?: CommunicationDeliveryStatus;
  recipient?: string;
  countryCode?: string;
  cursor?: string;
  limit: number;
}) {
  const limit = Math.min(filters.limit, 100);
  const where: Prisma.CommunicationDeliveryLogWhereInput = {
      ...(filters.channel ? { channel: filters.channel } : {}),
      ...(filters.providerId ? { providerId: filters.providerId } : {}),
      ...(filters.status ? { status: filters.status } : {}),
      ...(filters.recipient ? { recipient: { contains: filters.recipient, mode: 'insensitive' } } : {}),
      ...(filters.countryCode ? { countryCode: filters.countryCode } : {}),
  };
  if (filters.cursor) {
    const decoded = decodeCursor(filters.cursor);
    where.AND = [
      ...(where.AND as Prisma.CommunicationDeliveryLogWhereInput[] ?? []),
      { OR: [{ createdAt: { lt: decoded.createdAt } }, { createdAt: decoded.createdAt, id: { lt: decoded.id } }] },
    ];
  }
  const logs = await prisma.communicationDeliveryLog.findMany({
    where,
    include: {
      provider: { select: { id: true, name: true, code: true } },
      template: { select: { id: true, purpose: true, language: true } },
    },
    take: limit + 1,
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
  });
  const hasNextPage = logs.length > limit;
  const items = hasNextPage ? logs.slice(0, -1) : logs;
  return {
    items,
    nextCursor: hasNextPage ? encodeCursor({ createdAt: items[items.length - 1].createdAt, id: items[items.length - 1].id }) : null,
    hasNextPage,
    limit,
  };
}

export async function getProviderAuditLogs(opts: { limit: number; cursor?: string }) {
  const limit = Math.min(opts.limit, 100);
  const where: Prisma.CommunicationProviderAuditLogWhereInput = {};
  if (opts.cursor) {
    const decoded = decodeCursor(opts.cursor);
    where.AND = [
      ...(where.AND as Prisma.CommunicationProviderAuditLogWhereInput[] ?? []),
      { OR: [{ createdAt: { lt: decoded.createdAt } }, { createdAt: decoded.createdAt, id: { lt: decoded.id } }] },
    ];
  }
  const logs = await prisma.communicationProviderAuditLog.findMany({
    where,
    include: {
      actorAdmin: { select: { id: true, email: true, username: true } },
      provider: { select: { id: true, name: true, code: true } },
    },
    take: limit + 1,
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
  });
  const hasNextPage = logs.length > limit;
  const items = hasNextPage ? logs.slice(0, -1) : logs;
  return {
    items,
    nextCursor: hasNextPage ? encodeCursor({ createdAt: items[items.length - 1].createdAt, id: items[items.length - 1].id }) : null,
    hasNextPage,
    limit,
  };
}

export async function listRoutingRules() {
  return prisma.communicationRoutingRule.findMany({
    include: {
      provider: { select: { id: true, name: true, code: true, type: true } },
      app: { select: { id: true, name: true, slug: true } },
    },
    orderBy: [{ channel: 'asc' }, { priority: 'asc' }],
  });
}

export async function listOtpTemplates() {
  return prisma.otpTemplate.findMany({
    orderBy: [{ channel: 'asc' }, { purpose: 'asc' }, { language: 'asc' }],
  });
}

export async function deleteRoutingRule(ruleId: string) {
  return prisma.communicationRoutingRule.delete({ where: { id: ruleId } });
}

export async function deleteOtpTemplate(templateId: string) {
  return prisma.otpTemplate.delete({ where: { id: templateId } });
}

export async function formatProviderResponse(providerId: string) {
  const provider = await prisma.communicationProvider.findUnique({
    where: { id: providerId },
    include: { credentials: { orderBy: { updatedAt: 'desc' } } },
  });
  if (!provider) throw new AppError('Provider not found.', 'NOT_FOUND', 404);
  return {
    ...provider,
    credentials: provider.credentials.map((credential) => ({
      ...credential,
      encryptedSecrets: undefined,
    })),
  };
}
