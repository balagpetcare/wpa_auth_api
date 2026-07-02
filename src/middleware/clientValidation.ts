// ⚠️ LEGACY / UNUSED (Phase 1 audit fix, see docs/wpa-central-auth-api-complete-audit.md)
// This middleware is NOT imported or wired into any route in this codebase
// (verified: no `clientValidation` reference anywhere under src/routes or
// src/modules). It previously contained an insecure, non-constant-time raw
// string comparison of a client secret against a hash
// (`client.clientSecretHash !== clientSecret`), left over from a draft/demo
// implementation. That has been replaced below with a proper SHA-256 hash +
// timing-safe comparison, consistent with how client secrets are hashed
// elsewhere in the codebase (see src/modules/clients/clients.routes.ts and
// admin.service.ts, which both use `createHash('sha256').update(raw).digest('hex')`).
// Do NOT wire this middleware into production routes without a fresh security
// review — it is kept only as a reference/starting point for future
// service-to-service (client_credentials) validation.

import { Request, Response, NextFunction } from 'express';
import { createHash, timingSafeEqual } from 'crypto';
import { prisma } from '../lib/db.js';
import { logger } from '../lib/logger.js';
import { AuthClientType, AuthClientStatus } from '@prisma/client';

// Constant-time comparison of a raw client secret against the stored SHA-256 hash.
function isValidClientSecret(rawSecret: string, storedHash: string | null): boolean {
  if (!rawSecret || !storedHash) return false;
  const candidateHash = createHash('sha256').update(rawSecret).digest('hex');
  const a = Buffer.from(candidateHash, 'utf8');
  const b = Buffer.from(storedHash, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export const validateClient = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const clientId = req.headers['x-client-id'] as string || req.query.client_id as string || req.body.client_id;
    const origin = req.get('origin');
    const redirectUri = req.query.redirect_uri as string || req.body.redirect_uri;

    if (!clientId) {
      return res.status(400).json({ error: 'invalid_client', error_description: 'Client ID is missing' });
    }

    const client = await prisma.authClient.findUnique({
      where: { clientId }
    });

    if (!client || client.status !== AuthClientStatus.ACTIVE) {
      await logSecurityEvent('failed_client_validation', clientId, origin, 'Client not found or inactive', req);
      return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials' });
    }

    // Attach client to request for downstream handlers
    (req as any).authClient = client;

    // Service to Service validation
    if (client.type === AuthClientType.SERVICE) {
      const clientSecret = req.headers['x-client-secret'] as string || req.body.client_secret;

      if (!isValidClientSecret(clientSecret, client.clientSecretHash)) {
        // For security, if secret is invalid:
        await logSecurityEvent('failed_client_validation', clientId, origin, 'Invalid client secret', req);
        return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials' });
      }
    }

    // Origin validation for frontend apps
    if (origin && client.type !== AuthClientType.SERVICE) {
      if (!client.allowedOrigins.includes(origin)) {
        await logSecurityEvent('invalid_origin', clientId, origin, `Origin ${origin} not allowed`, req);
        return res.status(403).json({ error: 'unauthorized_client', error_description: 'Origin not allowed' });
      }
    }

    // Redirect URI validation
    if (redirectUri && client.type !== AuthClientType.SERVICE) {
      if (!client.redirectUris.includes(redirectUri)) {
        await logSecurityEvent('invalid_redirect_uri', clientId, origin, `Redirect URI ${redirectUri} not allowed`, req);
        return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect URI' });
      }
    }

    next();
  } catch (error) {
    logger.error({ err: error }, 'Client validation error');
    res.status(500).json({ error: 'server_error', error_description: 'Internal server error' });
  }
};

async function logSecurityEvent(action: string, clientId: string, origin: string | undefined, details: string, req: Request) {
  try {
    // Avoid logging secrets
    logger.warn({
      event: 'Security Audit',
      action,
      clientId,
      origin,
      details,
      ip: req.ip,
    });

    await prisma.securityEvent.create({
      data: {
        type: 'SUSPICIOUS_OAUTH',
        severity: 'MEDIUM',
        ipAddress: req.ip as string,
        userAgent: req.headers['user-agent'] as string,
        metadata: {
          action,
          clientId,
          origin,
          details
        }
      }
    });
  } catch (e) {
    logger.error({ err: e }, 'Failed to save security event');
  }
}
