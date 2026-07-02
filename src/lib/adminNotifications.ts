import { AdminNotificationCategory, AdminNotificationSeverity, Prisma } from '@prisma/client';
import { prisma } from './db.js';
import { AppError } from './errors.js';
import { enqueueCommunicationJob } from './communicationQueue.js';

type CreateAdminNotificationInput = {
  userId?: string | null;
  type: string;
  title: string;
  message: string;
  severity: AdminNotificationSeverity;
  category: AdminNotificationCategory;
  actionUrl?: string | null;
  metadata?: Prisma.InputJsonValue;
};

export function sanitizeAdminActionUrl(actionUrl?: string | null) {
  if (!actionUrl) return null;
  if (!actionUrl.startsWith('/')) {
    throw new AppError('Notification action URLs must be internal admin routes.', 'VALIDATION_ERROR', 400);
  }
  if (actionUrl.startsWith('//')) {
    throw new AppError('Notification action URLs must be internal admin routes.', 'VALIDATION_ERROR', 400);
  }
  return actionUrl;
}

export async function createAdminNotification(input: CreateAdminNotificationInput) {
  const queueResult = await enqueueCommunicationJob({
    type: 'send_admin_notification',
    payload: {
      type: input.type,
      title: input.title,
      message: input.message,
      severity: input.severity,
      category: input.category,
      actionUrl: input.actionUrl ?? null,
      userId: input.userId ?? null,
      metadata: (input.metadata as Record<string, unknown> | undefined) ?? undefined,
    },
  });

  if (queueResult.queued && !queueResult.deduped) {
    return { queued: true, jobId: queueResult.jobId };
  }

  if (queueResult.queued && queueResult.deduped) {
    return { queued: true, deduped: true, jobId: queueResult.jobId };
  }

  return prisma.adminNotification.create({
    data: {
      userId: input.userId ?? null,
      type: input.type,
      title: input.title,
      message: input.message,
      severity: input.severity,
      category: input.category,
      actionUrl: sanitizeAdminActionUrl(input.actionUrl),
      metadata: input.metadata,
    },
  });
}

export async function createAdminNotificationRecord(input: CreateAdminNotificationInput) {
  return prisma.adminNotification.create({
    data: {
      userId: input.userId ?? null,
      type: input.type,
      title: input.title,
      message: input.message,
      severity: input.severity,
      category: input.category,
      actionUrl: sanitizeAdminActionUrl(input.actionUrl),
      metadata: input.metadata,
    },
  });
}
