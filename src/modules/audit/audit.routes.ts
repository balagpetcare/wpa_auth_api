// ⚠️ LEGACY / UNMOUNTED (Phase 1 audit fix, see docs/wpa-central-auth-api-complete-audit.md)
// This router is NOT mounted in src/routes/index.ts. It previously exposed
// /api/v1/audit with only `authGuard` (no admin/permission check), letting any
// authenticated user read the full audit log (sensitive data exposure). A fully
// admin-guarded equivalent exists under /admin/audit-logs in
// src/modules/admin/admin.routes.ts + admin.service.ts. Do not re-mount this
// router without adding `authGuard, requireAdmin` (and ideally requirePermission)
// at the router level.

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
