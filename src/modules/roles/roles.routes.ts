// ⚠️ LEGACY / UNMOUNTED (Phase 1 audit fix, see docs/wpa-central-auth-api-complete-audit.md)
// This router is NOT mounted in src/routes/index.ts. It previously exposed
// /api/v1/roles with only `authGuard` (no admin/permission check), letting any
// authenticated user create roles. A fully admin-guarded equivalent exists under
// /admin/roles in src/modules/admin/admin.routes.ts + admin.service.ts. Do not
// re-mount this router without adding `authGuard, requireAdmin` (and ideally
// requirePermission) at the router level.

import { Router } from 'express';
import { prisma } from '../../lib/db.js';
import { authGuard } from '../../middleware/auth.js';
import { validateBody } from '../../middleware/validate.js';
import { z } from 'zod';

const router = Router();

const roleSchema = z.object({
  name: z.string().min(2),
  description: z.string().optional(),
});

router.post('/', authGuard, validateBody(roleSchema), async (req, res, next) => {
  try {
    const role = await prisma.role.create({ data: req.body });
    res.status(201).json({ success: true, role });
  } catch (err) {
    next(err);
  }
});

router.get('/', authGuard, async (_req, res, next) => {
  try {
    const roles = await prisma.role.findMany({ orderBy: { name: 'asc' } });
    res.json({ success: true, roles });
  } catch (err) {
    next(err);
  }
});

export default router;
