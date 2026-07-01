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
