import { Router } from 'express';
import { prisma } from '../../lib/db.js';
import { authGuard } from '../../middleware/auth.js';
import { validateBody } from '../../middleware/validate.js';
import { z } from 'zod';
import { randomBytes, createHash } from 'crypto';

const router = Router();

const clientSchema = z.object({
  name: z.string().min(2),
  slug: z.string().min(2).regex(/^[a-z0-9-]+$/),
  type: z.enum(['FIRST_PARTY_APP', 'THIRD_PARTY_APP', 'SERVICE']),
  allowedOrigins: z.array(z.string()).default([]),
  redirectUris: z.array(z.string()).default([]),
  allowedScopes: z.array(z.string()).default(['openid', 'profile']),
});

router.post('/', authGuard, validateBody(clientSchema), async (req, res, next) => {
  try {
    const clientId = randomBytes(16).toString('hex');
    const rawSecret = randomBytes(32).toString('hex');
    const clientSecretHash = createHash('sha256').update(rawSecret).digest('hex');

    const client = await prisma.authClient.create({
      data: { ...req.body, clientId, clientSecretHash },
      select: { id: true, name: true, slug: true, type: true, clientId: true, status: true, createdAt: true },
    });

    // Return raw secret once — not stored in plain text
    res.status(201).json({ success: true, client, clientSecret: rawSecret });
  } catch (err) {
    next(err);
  }
});

router.get('/', authGuard, async (_req, res, next) => {
  try {
    const clients = await prisma.authClient.findMany({
      select: { id: true, name: true, slug: true, type: true, clientId: true, status: true, createdAt: true },
    });
    res.json({ success: true, clients });
  } catch (err) {
    next(err);
  }
});

router.post('/:id/rotate-secret', authGuard, async (req, res, next) => {
  try {
    const id = req.params.id as string;
    const client = await prisma.authClient.findUnique({ where: { id } });

    if (!client) {
      return res.status(404).json({ success: false, error: 'Client not found' });
    }

    const rawSecret = randomBytes(32).toString('hex');
    const clientSecretHash = createHash('sha256').update(rawSecret).digest('hex');

    await prisma.authClient.update({
      where: { id },
      data: { clientSecretHash },
    });

    // Audit log for secret rotation (don't log secrets)
    await prisma.auditLog.create({
      data: {
        action: 'CLIENT_UPDATED',
        resource: 'auth_clients',
        resourceId: id,
        userId: (req as any).user?.id,
        ipAddress: req.ip as string,
        userAgent: req.headers['user-agent'] as string,
        metadata: {
          clientId: client.clientId,
          detail: 'Client secret rotated'
        }
      }
    });

    res.json({ success: true, clientSecret: rawSecret });
  } catch (err) {
    next(err);
  }
});

export default router;
