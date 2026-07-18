import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import bcrypt from 'bcrypt';
import { OAuthProvider, Prisma, DeletionRequestSource, DeletionRequestStatus, DeletionRequestType, DeletionRequestEventType, UserStatus } from '@prisma/client';
import { prisma } from '../../lib/db.js';
import { config } from '../../config/index.js';
import { AppError } from '../../lib/errors.js';
import { writeAuditLog } from '../../lib/audit.js';
import { removeAvatarByUrl } from '../../lib/avatarStorage.js';
import { getClientIp } from '../../lib/antiAbuse.js';
import type { Request } from 'express';

type DeletionRequestRecord = Prisma.DeletionRequestGetPayload<{
  include: {
    events: true;
    user: {
      select: {
        id: true;
        email: true;
        username: true;
        displayName: true;
        status: true;
        createdAt: true;
        updatedAt: true;
        lastLoginAt: true;
      };
    };
  };
}>;

const ACTIVE_REQUEST_STATUSES: DeletionRequestStatus[] = [
  DeletionRequestStatus.PENDING_REVIEW,
  DeletionRequestStatus.SCHEDULED,
  DeletionRequestStatus.PROCESSING,
  DeletionRequestStatus.FAILED,
];

type PublicSummaryInput = Pick<
  DeletionRequestRecord,
  'confirmationCode' | 'requestType' | 'provider' | 'requestSource' | 'status' | 'requestedAt' | 'gracePeriodDeadlineAt' | 'processedAt' | 'failureReason'
>;

const ADMIN_LIST_SELECT = {
  id: true,
  confirmationCode: true,
  requestType: true,
  provider: true,
  requestSource: true,
  status: true,
  requestedAt: true,
  gracePeriodDeadlineAt: true,
  processedAt: true,
  cancelledAt: true,
  reviewedAt: true,
  failureReason: true,
  emailHash: true,
  emailReference: true,
  userId: true,
  sourceIp: true,
  sourceUserAgent: true,
  auditMetadata: true,
} satisfies Prisma.DeletionRequestSelect;

function normalizeEmail(value: string) {
  return value.trim().toLowerCase();
}

function hashEmail(value: string) {
  return createHash('sha256').update(normalizeEmail(value)).digest('hex');
}

function protectedEmailReference(email: string) {
  const normalized = normalizeEmail(email);
  const [localPart, domain] = normalized.split('@');
  if (!localPart || !domain) return normalized;
  const visible = localPart.length <= 2 ? `${localPart[0] ?? '*'}` : `${localPart.slice(0, 2)}***`;
  const domainVisible = domain.length <= 2 ? `${domain[0] ?? '*'}` : `${domain.slice(0, 2)}***`;
  return `${visible}@${domainVisible}`;
}

function createConfirmationCode() {
  return randomBytes(12).toString('hex');
}

function buildGraceDeadline(hours = config.DELETION_GRACE_PERIOD_HOURS) {
  return new Date(Date.now() + hours * 60 * 60 * 1000);
}

function publicStatusUrl(code: string) {
  return `${config.PUBLIC_WEBSITE_ORIGIN}/data-deletion/status/${code}`;
}

function safeFailureReason(message: string | null | undefined) {
  if (!message) return null;
  return message.slice(0, 300);
}

async function recordEvent(
  deletionRequestId: string,
  eventType: DeletionRequestEventType,
  metadata: Prisma.InputJsonValue | undefined,
  actor?: { userId?: string | null; adminId?: string | null; source?: string },
) {
  await prisma.deletionRequestEvent.create({
    data: {
      deletionRequestId,
      eventType,
      metadata,
      actorSource: actor?.source ?? 'SYSTEM',
      actorUserId: actor?.userId ?? null,
      actorAdminId: actor?.adminId ?? null,
    },
  });
}

function publicSummary(request: PublicSummaryInput) {
  return {
    confirmationCode: request.confirmationCode,
    requestType: request.requestType,
    provider: request.provider,
    requestSource: request.requestSource,
    status: request.status,
    requestedAt: request.requestedAt,
    gracePeriodDeadlineAt: request.gracePeriodDeadlineAt,
    processedAt: request.processedAt,
    failureReason: safeFailureReason(request.failureReason),
    canCancel: request.status === DeletionRequestStatus.SCHEDULED && (!!request.gracePeriodDeadlineAt && request.gracePeriodDeadlineAt > new Date()),
    statusUrl: publicStatusUrl(request.confirmationCode),
  };
}

async function findRequestByConfirmationCode(confirmationCode: string) {
  return prisma.deletionRequest.findUnique({
    where: { confirmationCode },
    include: {
      events: { orderBy: { createdAt: 'asc' } },
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });
}

async function getActiveDuplicate(input: {
  requestType: DeletionRequestType;
  provider?: OAuthProvider | null;
  userId?: string | null;
  emailHash?: string | null;
}) {
  return prisma.deletionRequest.findFirst({
    where: {
      requestType: input.requestType,
      status: { in: ACTIVE_REQUEST_STATUSES },
      ...(input.provider ? { provider: input.provider } : {}),
      ...(input.userId ? { userId: input.userId } : {}),
      ...(input.emailHash ? { emailHash: input.emailHash } : {}),
    },
    orderBy: { requestedAt: 'desc' },
  });
}

async function ensurePasswordIfPresent(userId: string, password: string | undefined | null) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, passwordHash: true, email: true, status: true },
  });
  if (!user) {
    throw new AppError('User not found.', 'NOT_FOUND', 404);
  }
  if (!user.passwordHash) return;
  if (!password) {
    throw new AppError('Current password is required to confirm account deletion.', 'CURRENT_PASSWORD_REQUIRED', 400);
  }
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    throw new AppError('Current password is incorrect.', 'CURRENT_PASSWORD_INCORRECT', 403);
  }
}

async function writeDeletionAudit(
  action:
    | 'ACCOUNT_DELETION_REQUESTED'
    | 'ACCOUNT_DELETION_CANCELLED'
    | 'ACCOUNT_DELETION_APPROVED'
    | 'ACCOUNT_DELETION_REJECTED'
    | 'ACCOUNT_DELETION_PROCESSING_STARTED'
    | 'ACCOUNT_DELETION_PROCESSING_COMPLETED'
    | 'ACCOUNT_DELETION_PROCESSING_FAILED'
    | 'DATA_DELETION_REQUESTED'
    | 'DATA_DELETION_CANCELLED'
    | 'DATA_DELETION_APPROVED'
    | 'DATA_DELETION_REJECTED'
    | 'DATA_DELETION_PROCESSING_STARTED'
    | 'DATA_DELETION_PROCESSING_COMPLETED'
    | 'DATA_DELETION_PROCESSING_FAILED',
  request: DeletionRequestRecord,
  req?: Request,
  metadata?: Prisma.InputJsonValue,
) {
  await writeAuditLog({
    userId: request.userId ?? undefined,
    action,
    resource: 'deletion_request',
    resourceId: request.id,
    metadata,
    req,
  });
}

async function revokeAndAnonymizeAccount(userId: string, req?: Request) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, avatarUrl: true, email: true, phone: true, username: true },
  });
  if (!user) {
    return { revokedSessions: 0, revokedRefreshTokens: 0, disconnectedIdentities: 0 };
  }

  const now = new Date();
  const [sessions, refreshTokens, oauthAccounts, apiKeys, authCodes, passwordResetTokens, emailVerificationTokens, userClientAccess, userRoles] = await prisma.$transaction([
    prisma.loginSession.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: now, revocationReason: 'ACCOUNT_DELETION' },
    }),
    prisma.refreshToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: now, revocationReason: 'ACCOUNT_DELETION' },
    }),
    prisma.oAuthAccount.deleteMany({ where: { userId } }),
    prisma.apiKey.deleteMany({ where: { userId } }),
    prisma.authorizationCode.deleteMany({ where: { userId } }),
    prisma.passwordResetToken.deleteMany({ where: { userId } }),
    prisma.emailVerificationToken.deleteMany({ where: { userId } }),
    prisma.userClientAccess.deleteMany({ where: { userId } }),
    prisma.userRole.deleteMany({ where: { userId } }),
  ]);

  await prisma.user.update({
    where: { id: userId },
    data: {
      status: UserStatus.DELETED,
      email: null,
      phone: null,
      username: null,
      passwordHash: null,
      displayName: null,
      avatarUrl: null,
      bio: null,
      department: null,
      interfacePreferences: Prisma.DbNull,
      jobTitle: null,
      lastLoginAt: null,
      lastSeenAt: null,
      lastPasswordChangedAt: null,
      country: null,
      state: null,
      city: null,
      timezone: null,
      externalRefId: null,
      registrationSource: null,
      riskScore: 0,
      failedLoginCount: 0,
      lastLoginIp: null,
      lastLoginIpCountry: null,
      lastLoginDeviceType: null,
      lastLoginOs: null,
      lastLoginBrowser: null,
      notificationPreferences: Prisma.DbNull,
      organization: null,
      emailVerifiedAt: null,
      phoneVerifiedAt: null,
    },
  });

  await removeAvatarByUrl(user.avatarUrl);

  return {
    revokedSessions: sessions.count,
    revokedRefreshTokens: refreshTokens.count,
    disconnectedIdentities: oauthAccounts.count,
    removedApiKeys: apiKeys.count,
    removedAuthCodes: authCodes.count,
    removedPasswordResetTokens: passwordResetTokens.count,
    removedEmailVerificationTokens: emailVerificationTokens.count,
    removedClientAccessRows: userClientAccess.count,
    removedRoleRows: userRoles.count,
  };
}

async function disconnectProviderData(request: DeletionRequestRecord, req?: Request) {
  if (!request.userId || !request.provider) {
    return { disconnectedIdentities: 0 };
  }

  const now = new Date();
  const result = await prisma.$transaction([
    prisma.oAuthAccount.deleteMany({
      where: {
        userId: request.userId,
        provider: request.provider,
      },
    }),
    prisma.refreshToken.updateMany({
      where: { userId: request.userId, revokedAt: null },
      data: { revokedAt: now, revocationReason: `DATA_DELETION_${request.provider}` },
    }),
  ]);

  return { disconnectedIdentities: result[0].count };
}

async function finalizeRequest(
  request: DeletionRequestRecord,
  status: DeletionRequestStatus,
  metadata: Prisma.InputJsonValue | undefined,
  req?: Request,
) {
  await prisma.deletionRequest.update({
    where: { id: request.id },
    data: {
      status,
      processedAt: new Date(),
      failureReason: status === DeletionRequestStatus.FAILED ? String((metadata as Record<string, unknown> | undefined)?.['failureReason'] ?? 'Deletion processing failed.') : null,
    },
  });
  await recordEvent(request.id, status === DeletionRequestStatus.COMPLETED ? DeletionRequestEventType.PROCESSING_COMPLETED : DeletionRequestEventType.PROCESSING_FAILED, metadata, { userId: request.userId, source: 'SYSTEM' });

  const auditAction = request.requestType === DeletionRequestType.ACCOUNT
    ? (status === DeletionRequestStatus.COMPLETED ? 'ACCOUNT_DELETION_PROCESSING_COMPLETED' : 'ACCOUNT_DELETION_PROCESSING_FAILED')
    : (status === DeletionRequestStatus.COMPLETED ? 'DATA_DELETION_PROCESSING_COMPLETED' : 'DATA_DELETION_PROCESSING_FAILED');

  await writeDeletionAudit(auditAction, request, req, metadata).catch(() => undefined);
}

export type DeletionRequestSummary = ReturnType<typeof publicSummary>;

export type DeletionRequestDetail = {
  id: string;
  confirmationCode: string;
  requestType: DeletionRequestType;
  provider: OAuthProvider | null;
  requestSource: DeletionRequestSource;
  status: DeletionRequestStatus;
  userId: string | null;
  emailHash: string | null;
  emailReference: string | null;
  requestedAt: Date;
  gracePeriodDeadlineAt: Date | null;
  processedAt: Date | null;
  cancelledAt: Date | null;
  reviewedAt: Date | null;
  failureReason: string | null;
  sourceIp: string | null;
  sourceUserAgent: string | null;
  auditMetadata: Prisma.JsonValue | null;
  user: DeletionRequestRecord['user'];
  events: DeletionRequestRecord['events'];
};

function toDetail(request: DeletionRequestRecord): DeletionRequestDetail {
  return {
    id: request.id,
    confirmationCode: request.confirmationCode,
    requestType: request.requestType,
    provider: request.provider,
    requestSource: request.requestSource,
    status: request.status,
    userId: request.userId,
    emailHash: request.emailHash,
    emailReference: request.emailReference,
    requestedAt: request.requestedAt,
    gracePeriodDeadlineAt: request.gracePeriodDeadlineAt,
    processedAt: request.processedAt,
    cancelledAt: request.cancelledAt,
    reviewedAt: request.reviewedAt,
    failureReason: request.failureReason,
    sourceIp: request.sourceIp,
    sourceUserAgent: request.sourceUserAgent,
    auditMetadata: request.auditMetadata as Prisma.JsonValue | null,
    user: request.user,
    events: request.events,
  };
}

async function createDeletionRequest(input: {
  requestType: DeletionRequestType;
  requestSource: DeletionRequestSource;
  email?: string | null;
  provider?: OAuthProvider | null;
  userId?: string | null;
  status: DeletionRequestStatus;
  gracePeriodDeadlineAt?: Date | null;
  auditMetadata?: Prisma.InputJsonValue;
  metaPayload?: Prisma.InputJsonValue;
  req?: Request;
}) {
  const email = input.email ? normalizeEmail(input.email) : null;
  const emailHash = email ? hashEmail(email) : null;
  const emailReference = email ? protectedEmailReference(email) : null;

  const duplicate = await getActiveDuplicate({
    requestType: input.requestType,
    provider: input.provider ?? null,
    userId: input.userId ?? null,
    emailHash: emailHash ?? null,
  });

  if (duplicate) {
    const existing = await findRequestByConfirmationCode(duplicate.confirmationCode);
    if (existing) return toDetail(existing);
  }

  const confirmationCode = createConfirmationCode();
  const created = await prisma.deletionRequest.create({
    data: {
      confirmationCode,
      requestType: input.requestType,
      requestSource: input.requestSource,
      provider: input.provider ?? null,
      userId: input.userId ?? null,
      emailHash,
      emailReference,
      status: input.status,
      gracePeriodDeadlineAt: input.gracePeriodDeadlineAt ?? null,
      auditMetadata: input.auditMetadata,
      metaPayload: input.metaPayload,
      sourceIp: input.req ? getClientIp(input.req) : undefined,
      sourceUserAgent: input.req?.headers['user-agent']?.toString(),
    },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });

  await recordEvent(created.id, DeletionRequestEventType.REQUEST_CREATED, {
    requestType: created.requestType,
    requestSource: created.requestSource,
    provider: created.provider,
    emailHash: created.emailHash,
  }, {
    userId: created.userId,
    source: created.requestSource,
  });

  const auditAction = created.requestType === DeletionRequestType.ACCOUNT
    ? 'ACCOUNT_DELETION_REQUESTED'
    : 'DATA_DELETION_REQUESTED';
  await writeDeletionAudit(auditAction, created, input.req, {
    requestSource: created.requestSource,
    provider: created.provider,
    status: created.status,
  }).catch(() => undefined);

  return toDetail(created);
}

export async function requestAuthenticatedAccountDeletion(opts: {
  userId: string;
  password?: string | null;
  req: Request;
}) {
  await ensurePasswordIfPresent(opts.userId, opts.password);
  const request = await createDeletionRequest({
    requestType: DeletionRequestType.ACCOUNT,
    requestSource: DeletionRequestSource.AUTHENTICATED_WEB,
    userId: opts.userId,
    status: DeletionRequestStatus.SCHEDULED,
    gracePeriodDeadlineAt: buildGraceDeadline(),
    req: opts.req,
  });

  return {
    request,
    statusUrl: publicStatusUrl(request.confirmationCode),
  };
}

export async function requestPublicDeletion(input: {
  email: string;
  requestType: DeletionRequestType;
  provider?: OAuthProvider | null;
  explanation?: string | null;
  req: Request;
}) {
  const normalizedEmail = normalizeEmail(input.email);
  const user = await prisma.user.findFirst({
    where: { email: normalizedEmail },
    select: { id: true },
  });

  const request = await createDeletionRequest({
    requestType: input.requestType,
    requestSource: DeletionRequestSource.PUBLIC_WEB,
    email: normalizedEmail,
    provider: input.provider ?? null,
    userId: user?.id ?? null,
    status: DeletionRequestStatus.PENDING_REVIEW,
    auditMetadata: {
      explanation: input.explanation ?? null,
      emailHash: hashEmail(normalizedEmail),
    },
    req: input.req,
  });

  return {
    request,
    statusUrl: publicStatusUrl(request.confirmationCode),
  };
}

export async function requestMetaDeletionCallback(input: {
  signedRequest: string;
  req: Request;
}) {
  const decoded = decodeMetaSignedRequest(input.signedRequest);
  const providerAccountId = typeof decoded?.user_id === 'string' ? decoded.user_id : null;
  const email = typeof decoded?.email === 'string' ? decoded.email : null;
  const provider = OAuthProvider.FACEBOOK;

  let userId: string | null = null;
  if (providerAccountId) {
    const account = await prisma.oAuthAccount.findFirst({
      where: { provider, providerAccountId },
      select: { userId: true },
    });
    userId = account?.userId ?? null;
  }
  if (!userId && email) {
    const user = await prisma.user.findFirst({
      where: { email: normalizeEmail(email) },
      select: { id: true },
    });
    userId = user?.id ?? null;
  }

  const request = await createDeletionRequest({
    requestType: DeletionRequestType.DATA,
    requestSource: DeletionRequestSource.META_CALLBACK,
    email,
    provider,
    userId,
    status: DeletionRequestStatus.SCHEDULED,
    gracePeriodDeadlineAt: new Date(),
    metaPayload: decoded as Prisma.InputJsonValue,
    req: input.req,
  });

  const processed = await processDeletionRequest(request.confirmationCode, input.req, { skipGraceCheck: true });
  return {
    confirmation_code: request.confirmationCode,
    url: publicStatusUrl(request.confirmationCode),
    status: processed.status,
  };
}

function base64UrlDecode(value: string) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4;
  const padded = normalized + (pad === 0 ? '' : '='.repeat(4 - pad));
  return Buffer.from(padded, 'base64');
}

function decodeMetaSignedRequest(signedRequest: string) {
  const [encodedSignature, encodedPayload] = signedRequest.split('.', 2);
  if (!encodedSignature || !encodedPayload) {
    throw new AppError('Invalid Meta signed request.', 'VALIDATION_ERROR', 400);
  }

  const signature = base64UrlDecode(encodedSignature);
  const payload = base64UrlDecode(encodedPayload);
  const secret = config.FACEBOOK_APP_SECRET;
  if (!secret) {
    throw new AppError('Meta callback is not configured.', 'PROVIDER_DISABLED', 503);
  }

  const digest = createHmac('sha256', secret).update(payload).digest();
  if (digest.length !== signature.length || !timingSafeEqual(digest, signature)) {
    throw new AppError('Invalid Meta signed request signature.', 'FORBIDDEN', 403);
  }

  try {
    return JSON.parse(payload.toString('utf8')) as Record<string, unknown>;
  } catch {
    throw new AppError('Meta signed request payload could not be parsed.', 'VALIDATION_ERROR', 400);
  }
}

export async function getDeletionStatusByConfirmationCode(confirmationCode: string) {
  const request = await findRequestByConfirmationCode(confirmationCode);
  if (!request) {
    throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
  }

  if (request.status === DeletionRequestStatus.SCHEDULED && request.gracePeriodDeadlineAt && request.gracePeriodDeadlineAt <= new Date()) {
    await processDeletionRequest(confirmationCode, undefined, { skipGraceCheck: true });
    const refreshed = await findRequestByConfirmationCode(confirmationCode);
    if (!refreshed) {
      throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
    }
    return {
      ...publicSummary(refreshed),
      confirmationCode: refreshed.confirmationCode,
    };
  }

  return {
    ...publicSummary(request),
    confirmationCode: request.confirmationCode,
  };
}

export async function cancelDeletionRequestByConfirmationCode(confirmationCode: string, req?: Request) {
  const request = await findRequestByConfirmationCode(confirmationCode);
  if (!request) {
    throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
  }
  if (request.status !== DeletionRequestStatus.SCHEDULED || !request.gracePeriodDeadlineAt || request.gracePeriodDeadlineAt <= new Date()) {
    throw new AppError('This deletion request can no longer be cancelled.', 'FORBIDDEN', 403);
  }

  const updated = await prisma.deletionRequest.update({
    where: { id: request.id },
    data: {
      status: DeletionRequestStatus.CANCELLED,
      cancelledAt: new Date(),
    },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });

  await recordEvent(updated.id, DeletionRequestEventType.CANCELLED, { reason: 'public_cancellation' }, { userId: updated.userId, source: 'PUBLIC' });
  await writeDeletionAudit(
    updated.requestType === DeletionRequestType.ACCOUNT ? 'ACCOUNT_DELETION_CANCELLED' : 'DATA_DELETION_CANCELLED',
    updated,
    req,
    { confirmationCode: updated.confirmationCode, cancelledAt: updated.cancelledAt },
  );

  return toDetail(updated);
}

export async function cancelDeletionRequestById(requestId: string, req?: Request) {
  const request = await prisma.deletionRequest.findUnique({
    where: { id: requestId },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });
  if (!request) {
    throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
  }
  if (request.status !== DeletionRequestStatus.SCHEDULED || !request.gracePeriodDeadlineAt || request.gracePeriodDeadlineAt <= new Date()) {
    throw new AppError('This deletion request can no longer be cancelled.', 'FORBIDDEN', 403);
  }

  const updated = await prisma.deletionRequest.update({
    where: { id: request.id },
    data: {
      status: DeletionRequestStatus.CANCELLED,
      cancelledAt: new Date(),
    },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });

  await recordEvent(updated.id, DeletionRequestEventType.CANCELLED, { reason: 'authenticated_cancellation' }, { userId: updated.userId, source: 'USER' });
  await writeDeletionAudit(
    updated.requestType === DeletionRequestType.ACCOUNT ? 'ACCOUNT_DELETION_CANCELLED' : 'DATA_DELETION_CANCELLED',
    updated,
    req,
    { confirmationCode: updated.confirmationCode, cancelledAt: updated.cancelledAt },
  );

  return toDetail(updated);
}

export async function approveDeletionRequest(requestId: string, adminId: string, req?: Request) {
  const request = await prisma.deletionRequest.findUnique({
    where: { id: requestId },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });
  if (!request) throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
  if (request.status !== DeletionRequestStatus.PENDING_REVIEW && request.status !== DeletionRequestStatus.FAILED) {
    throw new AppError('This request cannot be approved in its current state.', 'FORBIDDEN', 403);
  }

  const updated = await prisma.deletionRequest.update({
    where: { id: requestId },
    data: {
      status: DeletionRequestStatus.SCHEDULED,
      reviewedAt: new Date(),
      reviewedByAdminId: adminId,
      gracePeriodDeadlineAt: buildGraceDeadline(),
      failureReason: null,
    },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });

  await recordEvent(updated.id, DeletionRequestEventType.APPROVED, { reviewedByAdminId: adminId }, { adminId, source: 'ADMIN' });
  await writeDeletionAudit(
    updated.requestType === DeletionRequestType.ACCOUNT ? 'ACCOUNT_DELETION_APPROVED' : 'DATA_DELETION_APPROVED',
    updated,
    req,
    { reviewedByAdminId: adminId, gracePeriodDeadlineAt: updated.gracePeriodDeadlineAt },
  );

  return toDetail(updated);
}

export async function rejectDeletionRequest(requestId: string, adminId: string, reason: string | null | undefined, req?: Request) {
  const request = await prisma.deletionRequest.findUnique({
    where: { id: requestId },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });
  if (!request) throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
  if (request.status === DeletionRequestStatus.COMPLETED || request.status === DeletionRequestStatus.CANCELLED) {
    throw new AppError('This request is already closed.', 'FORBIDDEN', 403);
  }

  const updated = await prisma.deletionRequest.update({
    where: { id: requestId },
    data: {
      status: DeletionRequestStatus.REJECTED,
      reviewedAt: new Date(),
      reviewedByAdminId: adminId,
      failureReason: reason?.slice(0, 300) ?? null,
    },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });

  await recordEvent(updated.id, DeletionRequestEventType.REJECTED, { reviewedByAdminId: adminId, reason: reason ?? null }, { adminId, source: 'ADMIN' });
  await writeDeletionAudit(
    updated.requestType === DeletionRequestType.ACCOUNT ? 'ACCOUNT_DELETION_REJECTED' : 'DATA_DELETION_REJECTED',
    updated,
    req,
    { reviewedByAdminId: adminId, reason: reason ?? null },
  );

  return toDetail(updated);
}

export async function retryDeletionRequest(requestId: string, adminId: string, req?: Request) {
  const request = await prisma.deletionRequest.findUnique({
    where: { id: requestId },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });
  if (!request) throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
  if (request.status !== DeletionRequestStatus.FAILED) {
    throw new AppError('Only failed requests can be retried.', 'FORBIDDEN', 403);
  }

  const updated = await prisma.deletionRequest.update({
    where: { id: requestId },
    data: {
      status: DeletionRequestStatus.SCHEDULED,
      reviewedAt: new Date(),
      reviewedByAdminId: adminId,
      gracePeriodDeadlineAt: new Date(),
      failureReason: null,
    },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });

  await recordEvent(updated.id, DeletionRequestEventType.STATUS_CHANGED, { reviewedByAdminId: adminId, action: 'retry' }, { adminId, source: 'ADMIN' });
  await writeDeletionAudit(
    updated.requestType === DeletionRequestType.ACCOUNT ? 'ACCOUNT_DELETION_APPROVED' : 'DATA_DELETION_APPROVED',
    updated,
    req,
    { action: 'retry', reviewedByAdminId: adminId },
  );

  return toDetail(updated);
}

export async function listDeletionRequests(opts: {
  status?: DeletionRequestStatus | 'ALL';
  requestType?: DeletionRequestType | 'ALL';
  provider?: OAuthProvider | 'ALL';
  requestSource?: DeletionRequestSource | 'ALL';
  search?: string;
  page?: number;
  limit?: number;
}) {
  const page = Math.max(1, opts.page ?? 1);
  const limit = Math.min(Math.max(opts.limit ?? 20, 1), 100);
  const where: Prisma.DeletionRequestWhereInput = {};
  if (opts.status && opts.status !== 'ALL') where.status = opts.status;
  if (opts.requestType && opts.requestType !== 'ALL') where.requestType = opts.requestType;
  if (opts.provider && opts.provider !== 'ALL') where.provider = opts.provider;
  if (opts.requestSource && opts.requestSource !== 'ALL') where.requestSource = opts.requestSource;
  if (opts.search) {
    const s = { contains: opts.search, mode: Prisma.QueryMode.insensitive };
    where.OR = [
      { confirmationCode: s },
      { emailHash: s },
      { emailReference: s },
      { userId: s },
    ];
  }

  const [items, total] = await Promise.all([
    prisma.deletionRequest.findMany({
      where,
      orderBy: [{ requestedAt: 'desc' }, { id: 'desc' }],
      skip: (page - 1) * limit,
      take: limit,
      select: ADMIN_LIST_SELECT,
    }),
    prisma.deletionRequest.count({ where }),
  ]);

  return {
    items,
    total,
    page,
    pageSize: limit,
    totalPages: Math.max(1, Math.ceil(total / limit)),
  };
}

export async function getDeletionRequestDetail(requestId: string) {
  const request = await findRequestByConfirmationCode(requestId).catch(() => null);
  if (!request) {
    const byId = await prisma.deletionRequest.findUnique({
      where: { id: requestId },
      include: {
        events: { orderBy: { createdAt: 'asc' } },
        user: {
          select: {
            id: true,
            email: true,
            username: true,
            displayName: true,
            status: true,
            createdAt: true,
            updatedAt: true,
            lastLoginAt: true,
          },
        },
      },
    });
    if (!byId) throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
    return toDetail(byId);
  }
  return toDetail(request);
}

export async function processDeletionRequestById(requestId: string, req?: Request, options?: { skipGraceCheck?: boolean }) {
  const request = await prisma.deletionRequest.findUnique({
    where: { id: requestId },
    include: {
      events: true,
      user: {
        select: {
          id: true,
          email: true,
          username: true,
          displayName: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          lastLoginAt: true,
        },
      },
    },
  });
  if (!request) throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
  return processDeletionRecord(request, req, options);
}

export async function processDeletionRequest(confirmationCode: string, req?: Request, options?: { skipGraceCheck?: boolean }) {
  const request = await findRequestByConfirmationCode(confirmationCode);
  if (!request) throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
  return processDeletionRecord(request, req, options);
}

async function processDeletionRecord(
  request: DeletionRequestRecord,
  req?: Request,
  options?: { skipGraceCheck?: boolean },
) {
  if (request.status === DeletionRequestStatus.COMPLETED || request.status === DeletionRequestStatus.CANCELLED || request.status === DeletionRequestStatus.REJECTED) {
    return toDetail(request);
  }

  if (!options?.skipGraceCheck) {
    if (request.status === DeletionRequestStatus.SCHEDULED && request.gracePeriodDeadlineAt && request.gracePeriodDeadlineAt > new Date()) {
      return toDetail(request);
    }
  }

  const claimed = await prisma.deletionRequest.updateMany({
    where: {
      id: request.id,
      status: { in: [DeletionRequestStatus.SCHEDULED, DeletionRequestStatus.FAILED, DeletionRequestStatus.PENDING_REVIEW] },
    },
    data: {
      status: DeletionRequestStatus.PROCESSING,
    },
  });

  if (claimed.count === 0) {
    const current = await findRequestByConfirmationCode(request.confirmationCode);
    if (!current) throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);
    return toDetail(current);
  }

  const processingRequest = await findRequestByConfirmationCode(request.confirmationCode);
  if (!processingRequest) throw new AppError('Deletion request not found.', 'NOT_FOUND', 404);

  await recordEvent(processingRequest.id, DeletionRequestEventType.PROCESSING_STARTED, {
    requestType: processingRequest.requestType,
    provider: processingRequest.provider,
  }, { userId: processingRequest.userId, source: 'SYSTEM' });

  await writeDeletionAudit(
    processingRequest.requestType === DeletionRequestType.ACCOUNT ? 'ACCOUNT_DELETION_PROCESSING_STARTED' : 'DATA_DELETION_PROCESSING_STARTED',
    processingRequest,
    req,
    { provider: processingRequest.provider, userId: processingRequest.userId },
  ).catch(() => undefined);

  try {
    if (processingRequest.requestType === DeletionRequestType.ACCOUNT) {
      if (processingRequest.userId) {
        const counts = await revokeAndAnonymizeAccount(processingRequest.userId, req);
        await recordEvent(processingRequest.id, DeletionRequestEventType.SOCIAL_IDENTITY_DISCONNECTED, counts as Prisma.InputJsonValue, { userId: processingRequest.userId, source: 'SYSTEM' });
        await finalizeRequest(processingRequest, DeletionRequestStatus.COMPLETED, counts as Prisma.InputJsonValue, req);
        return {
          ...toDetail((await findRequestByConfirmationCode(processingRequest.confirmationCode)) ?? processingRequest),
          processing: counts,
        };
      }

      await finalizeRequest(processingRequest, DeletionRequestStatus.COMPLETED, { note: 'No linked user was found.' }, req);
      return toDetail((await findRequestByConfirmationCode(processingRequest.confirmationCode)) ?? processingRequest);
    }

    if (processingRequest.provider) {
      const counts = await disconnectProviderData(processingRequest, req);
      await finalizeRequest(processingRequest, DeletionRequestStatus.COMPLETED, counts as Prisma.InputJsonValue, req);
      return {
        ...toDetail((await findRequestByConfirmationCode(processingRequest.confirmationCode)) ?? processingRequest),
        processing: counts,
      };
    }

    throw new AppError('Provider-specific data deletion requires a provider.', 'VALIDATION_ERROR', 400);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    await prisma.deletionRequest.update({
      where: { id: processingRequest.id },
      data: {
        status: DeletionRequestStatus.FAILED,
        processedAt: new Date(),
        failureReason: reason.slice(0, 300),
      },
    });
    await recordEvent(processingRequest.id, DeletionRequestEventType.PROCESSING_FAILED, { reason }, { userId: processingRequest.userId, source: 'SYSTEM' }).catch(() => undefined);
    await writeDeletionAudit(
      processingRequest.requestType === DeletionRequestType.ACCOUNT ? 'ACCOUNT_DELETION_PROCESSING_FAILED' : 'DATA_DELETION_PROCESSING_FAILED',
      processingRequest,
      req,
      { reason },
    ).catch(() => undefined);
    throw new AppError('Deletion processing failed.', 'PROCESSING_FAILED', 500);
  }
}

export async function processDueDeletionRequests(limit = 25) {
  const dueRequests = await prisma.deletionRequest.findMany({
    where: {
      status: DeletionRequestStatus.SCHEDULED,
      gracePeriodDeadlineAt: { lte: new Date() },
    },
    orderBy: [{ gracePeriodDeadlineAt: 'asc' }, { requestedAt: 'asc' }],
    take: limit,
  });

  let processed = 0;
  for (const request of dueRequests) {
    try {
      const full = await findRequestByConfirmationCode(request.confirmationCode);
      if (!full) continue;
      await processDeletionRecord(full, undefined, { skipGraceCheck: true });
      processed += 1;
    } catch {
      // Best-effort worker. The request is marked FAILED by processDeletionRecord on error.
    }
  }

  return { processed };
}
