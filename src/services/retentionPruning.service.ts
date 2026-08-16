import { Prisma } from '@prisma/client';
import { prisma } from '../lib/db.js';
import { config } from '../config/index.js';
import { logger } from '../lib/logger.js';

type PruneResult = {
  name: string;
  candidates: number;
  deleted: number;
};

function cutoffDate(days: number) {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000);
}

async function pruneByIdBatches<T extends { id: string }>(opts: {
  name: string;
  where: any;
  batchSize: number;
  dryRun: boolean;
  model: {
    count(args: { where: any }): Promise<number>;
    findMany(args: { where: any; select: { id: true }; orderBy: [{ createdAt: 'asc' }, { id: 'asc' }]; take: number }): Promise<T[]>;
    deleteMany(args: { where: { id: { in: string[] } } }): Promise<{ count: number }>;
  };
}): Promise<PruneResult> {
  const candidates = await opts.model.count({ where: opts.where });
  if (opts.dryRun || candidates === 0) {
    return { name: opts.name, candidates, deleted: 0 };
  }

  let deleted = 0;
  while (true) {
    const rows = await opts.model.findMany({
      where: opts.where,
      select: { id: true },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: opts.batchSize,
    });
    if (rows.length === 0) break;
    const result = await opts.model.deleteMany({ where: { id: { in: rows.map((row) => row.id) } } });
    deleted += result.count;
    if (result.count < rows.length) break;
  }
  return { name: opts.name, candidates, deleted };
}

export async function runRetentionPruning(opts?: { dryRun?: boolean; batchSize?: number }) {
  const dryRun = Boolean(opts?.dryRun);
  const batchSize = opts?.batchSize ?? config.RETENTION_PRUNE_BATCH_SIZE;
  const now = new Date();

  const targets = [
    {
      name: 'AuditLog',
      retentionDays: config.AUDIT_LOG_RETENTION_DAYS,
      model: prisma.auditLog,
      where: { createdAt: { lt: cutoffDate(config.AUDIT_LOG_RETENTION_DAYS) } },
    },
    {
      name: 'SecurityEvent',
      retentionDays: config.SECURITY_EVENT_RETENTION_DAYS,
      model: prisma.securityEvent,
      where: { createdAt: { lt: cutoffDate(config.SECURITY_EVENT_RETENTION_DAYS) } },
    },
    {
      name: 'AdminNotification',
      retentionDays: config.ADMIN_NOTIFICATION_RETENTION_DAYS,
      model: prisma.adminNotification,
      where: {
        createdAt: { lt: cutoffDate(config.ADMIN_NOTIFICATION_RETENTION_DAYS) },
        OR: [{ dismissedAt: { not: null } }, { readAt: { not: null } }],
      },
    },
    {
      name: 'CommunicationDeliveryLog',
      retentionDays: config.COMMUNICATION_DELIVERY_LOG_RETENTION_DAYS,
      model: prisma.communicationDeliveryLog,
      where: { createdAt: { lt: cutoffDate(config.COMMUNICATION_DELIVERY_LOG_RETENTION_DAYS) } },
    },
    {
      name: 'CommunicationProviderAuditLog',
      retentionDays: config.COMMUNICATION_PROVIDER_AUDIT_LOG_RETENTION_DAYS,
      model: prisma.communicationProviderAuditLog,
      where: { createdAt: { lt: cutoffDate(config.COMMUNICATION_PROVIDER_AUDIT_LOG_RETENTION_DAYS) } },
    },
    {
      name: 'LoginSession',
      retentionDays: config.LOGIN_SESSION_RETENTION_DAYS,
      model: prisma.loginSession,
      where: {
        createdAt: { lt: cutoffDate(config.LOGIN_SESSION_RETENTION_DAYS) },
        OR: [{ revokedAt: { not: null } }, { expiresAt: { lt: now } }],
      },
    },
    {
      name: 'AuthorizationCode',
      retentionDays: config.AUTHORIZATION_CODE_RETENTION_DAYS,
      model: prisma.authorizationCode,
      where: {
        createdAt: { lt: cutoffDate(config.AUTHORIZATION_CODE_RETENTION_DAYS) },
        OR: [{ usedAt: { not: null } }, { expiresAt: { lt: now } }],
      },
    },
    {
      name: 'RefreshToken',
      retentionDays: config.REFRESH_TOKEN_RETENTION_DAYS,
      model: prisma.refreshToken,
      where: {
        createdAt: { lt: cutoffDate(config.REFRESH_TOKEN_RETENTION_DAYS) },
        OR: [{ revokedAt: { not: null } }, { expiresAt: { lt: now } }],
      },
    },
    {
      name: 'ServiceAccessToken',
      retentionDays: config.REFRESH_TOKEN_RETENTION_DAYS,
      model: prisma.serviceAccessToken,
      where: {
        createdAt: { lt: cutoffDate(config.REFRESH_TOKEN_RETENTION_DAYS) },
        OR: [{ revokedAt: { not: null } }, { expiresAt: { lt: now } }],
      },
    },
  ] as const;

  const results: PruneResult[] = [];
  for (const target of targets) {
    const result = await pruneByIdBatches({
      name: target.name,
      where: target.where,
      batchSize,
      dryRun,
      model: target.model as any,
    });
    results.push(result);
    logger.info({ target: target.name, retentionDays: target.retentionDays, candidates: result.candidates, deleted: result.deleted, dryRun }, 'Retention pruning result');
  }

  return results;
}
