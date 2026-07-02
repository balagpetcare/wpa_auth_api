import { AuditAction, SecurityEventType, SecurityEventSeverity, Prisma } from '@prisma/client';
import { prisma } from './db.js';
import { Request } from 'express';

export async function writeAuditLog(opts: {
  userId?: string;
  clientId?: string;
  action: AuditAction;
  resource?: string;
  resourceId?: string;
  metadata?: Prisma.InputJsonValue;
  req?: Request;
}) {
  await prisma.auditLog.create({
    data: {
      userId: opts.userId,
      clientId: opts.clientId,
      action: opts.action,
      resource: opts.resource,
      resourceId: opts.resourceId,
      metadata: opts.req?.requestId
        ? { ...(opts.metadata as Record<string, unknown> | undefined), requestId: opts.req.requestId }
        : opts.metadata,
      ipAddress: opts.req ? (opts.req.ip ?? opts.req.socket.remoteAddress) : undefined,
      userAgent: opts.req?.headers['user-agent'],
    },
  });
}

export async function writeSecurityEvent(opts: {
  userId?: string;
  type: SecurityEventType;
  severity: SecurityEventSeverity;
  metadata?: Prisma.InputJsonValue;
  req?: Request;
}) {
  await prisma.securityEvent.create({
    data: {
      userId: opts.userId,
      type: opts.type,
      severity: opts.severity,
      metadata: opts.req?.requestId
        ? { ...(opts.metadata as Record<string, unknown> | undefined), requestId: opts.req.requestId }
        : opts.metadata,
      ipAddress: opts.req ? (opts.req.ip ?? opts.req.socket.remoteAddress) : undefined,
      userAgent: opts.req?.headers['user-agent'],
    }
  });
}
