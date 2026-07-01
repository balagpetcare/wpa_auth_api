import { Router } from 'express';
import { prisma } from '../../lib/db.js';
import { authGuard } from '../../middleware/auth.js';

const router = Router();

router.get('/', authGuard, async (_req, res, next) => {
  try {
    const logs = await prisma.auditLog.findMany({
      orderBy: { createdAt: 'desc' },
      take: 200,
      select: {
        id: true,
        action: true,
        resource: true,
        resourceId: true,
        ipAddress: true,
        metadata: true,
        createdAt: true,
        user: { select: { id: true, email: true, username: true } },
      },
    });
    res.json({ success: true, logs });
  } catch (err) {
    next(err);
  }
});

export default router;
