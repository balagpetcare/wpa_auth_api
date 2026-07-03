import { createHash, timingSafeEqual } from 'crypto';
import { AuditAction, AuthClientStatus, AuthClientType, Prisma, SecurityEventSeverity, SecurityEventType } from '@prisma/client';
import type { Request } from 'express';
import { prisma } from '../../lib/db.js';
import { AppError } from '../../lib/errors.js';
import { config } from '../../config/index.js';
import { getClientIp } from '../../lib/antiAbuse.js';
import { getRedisClient } from '../../lib/redis.js';
import { writeAuditLog, writeSecurityEvent } from '../../lib/audit.js';
import { dispatchEmail, dispatchSms } from './communication.service.js';
import type { ExternalCommunicationEventInput } from './events.schemas.js';

type ExternalEventClient = {
  id: string;
  clientId: string;
  type: AuthClientType;
  allowedScopes: string[];
  status: AuthClientStatus;
  name: string;
};

type ExternalEventRecord = {
  id: string;
  event: string;
  idempotencyKey: string;
  channels: string[];
  status: string;
  resultJson: Prisma.JsonValue | null;
  client: ExternalEventClient;
};

type ApprovedChannelResult = {
  channel: 'sms' | 'email';
  accepted: boolean;
  queued: boolean;
  blocked: boolean;
  message?: string | null;
  result?: unknown;
};

const EVENT_CLIENT_RATE_LIMITS = {
  per15m: 20,
  perHour: 100,
  perDay: 500,
};

const externalEventModel = prisma as typeof prisma & {
  externalCommunicationEvent: {
    findUnique: (args: any) => Promise<ExternalEventRecord | null>;
    create: (args: any) => Promise<ExternalEventRecord>;
    update: (args: any) => Promise<ExternalEventRecord>;
  };
};

function sha256(value: string) {
  return createHash('sha256').update(value).digest('hex');
}

function safeCompareSecret(raw: string, storedHash: string | null | undefined) {
  if (!raw || !storedHash) return false;
  const a = Buffer.from(sha256(raw), 'utf8');
  const b = Buffer.from(storedHash, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function normalizePhoneForEvent(input: string) {
  let cleaned = input.trim().replace(/[^\d+]/g, '');
  if (!cleaned.startsWith('+') && cleaned.startsWith('01') && cleaned.length === 11) {
    cleaned = `+88${cleaned}`;
  } else if (!cleaned.startsWith('+')) {
    cleaned = `+${cleaned}`;
  }
  if (!/^\+[1-9]\d{7,14}$/.test(cleaned)) {
    throw new AppError('Invalid recipient phone number.', 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD', 400);
  }
  return cleaned;
}

function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatAmount(amount: number, currency: string, locale: string) {
  try {
    return new Intl.NumberFormat(locale === 'bn' ? 'bn-BD' : 'en-US', {
      style: 'currency',
      currency,
      maximumFractionDigits: 2,
    }).format(amount);
  } catch {
    return `${amount} ${currency}`;
  }
}

function getCommunicationScope(client: { allowedScopes: string[] }) {
  return client.allowedScopes.map((scope) => scope.trim().toLowerCase());
}

function supportsCommunicationEvents(client: { allowedScopes: string[] }) {
  const scopes = getCommunicationScope(client);
  if (!scopes.length) return true;
  return scopes.includes('communication:events')
    || scopes.includes('communication:transactional')
    || scopes.includes('communication:*')
    || scopes.includes('*');
}

function buildEventContent(input: ExternalCommunicationEventInput) {
  const eventLabel = {
    VACCINATION_PAYMENT_CONFIRMED: 'Vaccination payment',
    DONATION_PAYMENT_CONFIRMED: 'Donation payment',
    MEMBERSHIP_PAYMENT_CONFIRMED: 'Membership payment',
  }[input.event];
  const recipientName = input.recipient.name?.trim() || 'Customer';
  const campaignName = input.data.campaignName.trim();
  const bookingRef = input.data.bookingRef.trim();
  const paymentRef = input.data.paymentRef.trim();
  const amount = Number(input.data.amount);
  const currency = input.data.currency.trim().toUpperCase();
  const amountText = formatAmount(amount, currency, input.locale);
  const supportPhone = input.data.supportPhone?.trim() || input.recipient.phone?.trim() || '';
  const bookingSlipUrl = input.data.bookingSlipUrl?.trim();
  const sessionDate = input.data.sessionDate?.trim();
  const sessionTime = input.data.sessionTime?.trim();
  const venueName = input.data.venueName?.trim();
  const petCount = input.data.petCount === undefined ? undefined : Number(input.data.petCount);

  const summaryLines = [
    `Hello ${recipientName},`,
    '',
    `${campaignName} ${eventLabel.toLowerCase()} has been confirmed.`,
    `Booking reference: ${bookingRef}`,
    `Payment reference: ${paymentRef}`,
    `Amount: ${amountText}`,
    ...(petCount !== undefined ? [`Pet count: ${petCount}`] : []),
    ...(venueName ? [`Venue: ${venueName}`] : []),
    ...(sessionDate ? [`Date: ${sessionDate}`] : []),
    ...(sessionTime ? [`Time: ${sessionTime}`] : []),
    ...(bookingSlipUrl ? [`Slip: ${bookingSlipUrl}`] : []),
    ...(supportPhone ? [`Support: ${supportPhone}`] : []),
  ];

  const subject = `${campaignName} ${eventLabel.toLowerCase()} confirmed`;
  const text = summaryLines.join('\n');
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.6;color:#1f2937">
      <p>Hello ${escapeHtml(recipientName)},</p>
      <p><strong>${escapeHtml(campaignName)}</strong> payment has been confirmed.</p>
      <ul>
        <li><strong>Booking reference:</strong> ${escapeHtml(bookingRef)}</li>
        <li><strong>Payment reference:</strong> ${escapeHtml(paymentRef)}</li>
        <li><strong>Amount:</strong> ${escapeHtml(amountText)}</li>
        ${petCount !== undefined ? `<li><strong>Pet count:</strong> ${escapeHtml(String(petCount))}</li>` : ''}
        ${venueName ? `<li><strong>Venue:</strong> ${escapeHtml(venueName)}</li>` : ''}
        ${sessionDate ? `<li><strong>Date:</strong> ${escapeHtml(sessionDate)}</li>` : ''}
        ${sessionTime ? `<li><strong>Time:</strong> ${escapeHtml(sessionTime)}</li>` : ''}
        ${bookingSlipUrl ? `<li><strong>Booking slip:</strong> <a href="${escapeHtml(bookingSlipUrl)}">${escapeHtml(bookingSlipUrl)}</a></li>` : ''}
        ${supportPhone ? `<li><strong>Support:</strong> ${escapeHtml(supportPhone)}</li>` : ''}
      </ul>
      <p>Please keep this message for your records.</p>
    </div>
  `;

  const sms = [
    `${campaignName}: ${eventLabel.toLowerCase()} confirmed.`,
    `Booking ${bookingRef}`,
    `Payment ${paymentRef}`,
    `Amount ${amountText}`,
    ...(sessionDate ? [`Date ${sessionDate}`] : []),
    ...(sessionTime ? [`Time ${sessionTime}`] : []),
  ].join(' ');

  return { subject, text, html, sms, amount };
}

export async function enforceClientEventRateLimit(clientId: string, event: string, req: Request) {
  if (!config.COMMUNICATION_RATE_LIMIT_ENABLED) return;

  const redis = getRedisClient();
  if (!redis) return;

  const base = `communication:event:${clientId}:${event}`;
  const windows = [
    { key: `${base}:15m`, limit: EVENT_CLIENT_RATE_LIMITS.per15m, ttl: 15 * 60 },
    { key: `${base}:1h`, limit: EVENT_CLIENT_RATE_LIMITS.perHour, ttl: 60 * 60 },
    { key: `${base}:1d`, limit: EVENT_CLIENT_RATE_LIMITS.perDay, ttl: 24 * 60 * 60 },
  ];

  for (const window of windows) {
    const current = await redis.incr(window.key);
    if (current === 1) {
      await redis.expire(window.key, window.ttl);
    }
    if (current > window.limit) {
      await writeSecurityEvent({
        type: SecurityEventType.BRUTE_FORCE_DETECTED,
        severity: SecurityEventSeverity.HIGH,
        metadata: {
          area: 'external-communication-event',
          clientId,
          event,
          limitKey: window.key,
          requestId: req.requestId ?? null,
          sourceIp: getClientIp(req),
        } as Prisma.InputJsonValue,
        req,
      });
      throw new AppError('Please wait before submitting another communication event.', 'RATE_LIMITED', 429);
    }
  }
}

export async function authenticateExternalCommunicationClient(req: Request) {
  const clientId = String(req.header('x-client-id') ?? '').trim();
  const authHeader = String(req.header('authorization') ?? '').trim();

  if (!clientId || !authHeader.toLowerCase().startsWith('bearer ')) {
    throw new AppError('Invalid client credentials or event payload.', 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD', 401);
  }

  const rawSecret = authHeader.slice(7).trim();
  if (!rawSecret) {
    throw new AppError('Invalid client credentials or event payload.', 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD', 401);
  }

  const client = await prisma.authClient.findUnique({ where: { clientId } });
  if (!client || client.status !== AuthClientStatus.ACTIVE) {
    await writeSecurityEvent({
      type: SecurityEventType.INVALID_API_KEY,
      severity: SecurityEventSeverity.HIGH,
      metadata: {
        area: 'external-communication-event',
        clientId,
        requestId: req.requestId ?? null,
        sourceIp: getClientIp(req),
        reason: 'client_missing_or_inactive',
      } as Prisma.InputJsonValue,
      req,
    });
    throw new AppError('Invalid client credentials or event payload.', 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD', 401);
  }

  if (client.type !== AuthClientType.SERVICE && client.type !== AuthClientType.FIRST_PARTY_APP) {
    await writeSecurityEvent({
      type: SecurityEventType.UNAUTHORIZED_SCOPE,
      severity: SecurityEventSeverity.HIGH,
      metadata: {
        area: 'external-communication-event',
        clientId,
        requestId: req.requestId ?? null,
        sourceIp: getClientIp(req),
        reason: 'client_type_not_allowed',
        clientType: client.type,
      } as Prisma.InputJsonValue,
      req,
    });
    throw new AppError('Invalid client credentials or event payload.', 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD', 403);
  }

  if (!client.clientSecretHash || !safeCompareSecret(rawSecret, client.clientSecretHash)) {
    await writeSecurityEvent({
      type: SecurityEventType.INVALID_API_KEY,
      severity: SecurityEventSeverity.HIGH,
      metadata: {
        area: 'external-communication-event',
        clientId,
        requestId: req.requestId ?? null,
        sourceIp: getClientIp(req),
        reason: 'invalid_service_key',
      } as Prisma.InputJsonValue,
      req,
    });
    throw new AppError('Invalid client credentials or event payload.', 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD', 401);
  }

  if (!supportsCommunicationEvents(client)) {
    await writeSecurityEvent({
      type: SecurityEventType.UNAUTHORIZED_SCOPE,
      severity: SecurityEventSeverity.HIGH,
      metadata: {
        area: 'external-communication-event',
        clientId,
        requestId: req.requestId ?? null,
        sourceIp: getClientIp(req),
        reason: 'communication_events_scope_missing',
        allowedScopes: client.allowedScopes,
      } as Prisma.InputJsonValue,
      req,
    });
    throw new AppError('Invalid client credentials or event payload.', 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD', 403);
  }

  return client;
}

async function getExistingEvent(clientId: string, event: string, idempotencyKey: string): Promise<ExternalEventRecord | null> {
  return externalEventModel.externalCommunicationEvent.findUnique({
    where: {
      clientId_event_idempotencyKey: {
        clientId,
        event,
        idempotencyKey,
      },
    },
    include: {
      client: {
        select: {
          id: true,
          clientId: true,
          type: true,
          allowedScopes: true,
          status: true,
          name: true,
        },
      },
    },
  });
}

async function saveEventResult(eventId: string, result: Record<string, unknown>, status: string) {
  return externalEventModel.externalCommunicationEvent.update({
    where: { id: eventId },
    data: {
      status,
      resultJson: result as Prisma.InputJsonValue,
      processedAt: new Date(),
    },
  });
}

async function sendApprovedChannels(input: {
  req: Request;
  client: ExternalEventRecord['client'];
  payload: ExternalCommunicationEventInput;
  eventId: string;
}) {
  const content = buildEventContent(input.payload);
  const sourceIp = getClientIp(input.req);
  const environment = process.env.NODE_ENV === 'production' ? 'LIVE' : 'SANDBOX';
  const channelResults: ApprovedChannelResult[] = [];

  const sendSms = input.payload.channels.includes('sms') && input.payload.recipient.phone
    ? (async () => {
      const normalizedPhone = normalizePhoneForEvent(input.payload.recipient.phone!);
      try {
        const result = await dispatchSms({
          to: normalizedPhone,
          message: content.sms,
          purpose: 'GENERAL',
          clientId: input.client.id,
          req: input.req,
          environment,
        });
        return {
          channel: 'sms',
          accepted: true,
          queued: Boolean((result as { queued?: boolean }).queued),
          blocked: false,
          result,
        } satisfies ApprovedChannelResult;
      } catch (error) {
        const blocked = error instanceof AppError && (error.code === 'COMMUNICATION_RATE_LIMITED' || error.code === 'COMMUNICATION_BLOCKED' || error.code === 'VALIDATION_ERROR');
        return {
          channel: 'sms',
          accepted: false,
          queued: false,
          blocked,
          message: error instanceof Error ? error.message : 'SMS delivery failed.',
          result: { error: error instanceof Error ? error.message : String(error) },
        } satisfies ApprovedChannelResult;
      }
    })()
    : Promise.resolve(null);

  const sendEmail = input.payload.channels.includes('email') && input.payload.recipient.email
    ? (async () => {
      const recipientEmail = input.payload.recipient.email!.trim().toLowerCase();
      try {
        const result = await dispatchEmail({
          to: recipientEmail,
          subject: content.subject,
          text: content.text,
          html: content.html,
          purpose: 'GENERAL',
          clientId: input.client.id,
          req: input.req,
          environment,
        });
        return {
          channel: 'email',
          accepted: true,
          queued: Boolean((result as { queued?: boolean }).queued),
          blocked: false,
          result,
        } satisfies ApprovedChannelResult;
      } catch (error) {
        const blocked = error instanceof AppError && (error.code === 'COMMUNICATION_RATE_LIMITED' || error.code === 'COMMUNICATION_BLOCKED' || error.code === 'VALIDATION_ERROR');
        return {
          channel: 'email',
          accepted: false,
          queued: false,
          blocked,
          message: error instanceof Error ? error.message : 'Email delivery failed.',
          result: { error: error instanceof Error ? error.message : String(error) },
        } satisfies ApprovedChannelResult;
      }
    })()
    : Promise.resolve(null);

  const settled = await Promise.all([sendSms, sendEmail]);
  for (const item of settled) {
    if (item) channelResults.push(item);
  }

  const anyAccepted = channelResults.some((item) => item.accepted);
  const anyBlocked = channelResults.some((item) => item.blocked);
  const allFailed = channelResults.length > 0 && channelResults.every((item) => !item.accepted);

  const resultJson = {
    eventId: input.eventId,
    channels: channelResults,
    acceptedAt: new Date().toISOString(),
    sourceIp,
  };

  const status = anyAccepted ? 'QUEUED_OR_SENT' : anyBlocked ? 'BLOCKED' : 'FAILED';
  await saveEventResult(input.eventId, resultJson, status);

  await writeAuditLog({
    clientId: input.client.id,
    action: AuditAction.COMMUNICATION_EVENT_TRIGGERED,
    resource: 'communication-event',
    resourceId: input.eventId,
    metadata: {
      event: input.payload.event,
      channels: input.payload.channels,
      status,
      deduped: false,
      requestId: input.req.requestId ?? null,
      sourceIp,
      recipient: {
        name: input.payload.recipient.name ?? null,
        phone: input.payload.recipient.phone ? 'provided' : null,
        email: input.payload.recipient.email ? 'provided' : null,
      },
    } as Prisma.InputJsonValue,
    req: input.req,
  });

  if (!anyAccepted && allFailed) {
    const firstMessage = channelResults.find((item) => item.message)?.message ?? 'Unable to process the communication event.';
    throw new AppError(firstMessage ?? 'Unable to process the communication event.', anyBlocked ? 'COMMUNICATION_RATE_LIMITED' : 'COMMUNICATION_UNAVAILABLE', anyBlocked ? 429 : 503);
  }

  return {
    eventId: input.eventId,
    status,
    deduped: false,
    channels: input.payload.channels,
  };
}

export async function submitExternalCommunicationEvent(input: {
  req: Request;
  client: ExternalEventRecord['client'];
  payload: ExternalCommunicationEventInput;
  idempotencyKey: string;
}) {
  const eventRecord = await externalEventModel.externalCommunicationEvent.create({
    data: {
      clientId: input.client.id,
      event: input.payload.event,
      idempotencyKey: input.idempotencyKey,
      channels: input.payload.channels,
      recipientPhone: input.payload.recipient.phone ? normalizePhoneForEvent(input.payload.recipient.phone) : null,
      recipientEmail: input.payload.recipient.email ? input.payload.recipient.email.trim().toLowerCase() : null,
      recipientName: input.payload.recipient.name?.trim() ?? null,
      locale: input.payload.locale,
      payloadJson: input.payload as unknown as Prisma.InputJsonValue,
      status: 'PROCESSING',
      requestId: input.req.requestId ?? null,
      sourceIp: getClientIp(input.req),
    },
    include: {
      client: {
        select: {
          id: true,
          clientId: true,
          type: true,
          allowedScopes: true,
          status: true,
          name: true,
        },
      },
    },
  });

  return sendApprovedChannels({
    req: input.req,
    client: eventRecord.client,
    payload: input.payload,
    eventId: eventRecord.id,
  });
}

export async function recordExternalCommunicationEventDuplicate(input: {
  existing: ExternalEventRecord;
}) {
  await writeAuditLog({
    clientId: input.existing.client.id,
    action: AuditAction.COMMUNICATION_EVENT_TRIGGERED,
    resource: 'communication-event',
    resourceId: input.existing.id,
    metadata: {
      event: input.existing.event,
      channels: input.existing.channels,
      status: input.existing.status,
      deduped: true,
    } as Prisma.InputJsonValue,
  });

  return {
    eventId: input.existing.id,
    status: 'ALREADY_ACCEPTED',
    deduped: true,
    channels: input.existing.channels,
  };
}

export async function getOrCreateExternalCommunicationEvent(input: {
  req: Request;
  client: ExternalEventRecord['client'];
  payload: ExternalCommunicationEventInput;
  idempotencyKey: string;
}) {
  const existing = await getExistingEvent(input.client.id, input.payload.event, input.idempotencyKey);
  if (existing) {
    return { existing, deduped: true as const };
  }

  try {
    const result = await submitExternalCommunicationEvent(input);
    return { result, deduped: false as const };
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
      const duplicate = await getExistingEvent(input.client.id, input.payload.event, input.idempotencyKey);
      if (!duplicate) throw error;
      return { existing: duplicate, deduped: true as const };
    }
    throw error;
  }
}
