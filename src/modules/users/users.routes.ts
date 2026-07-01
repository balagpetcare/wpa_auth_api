import { Router } from 'express';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import { getCurrentUser } from '../auth/auth.service.js';

const router = Router();

router.get('/me', authGuard, async (req: AuthenticatedRequest, res, next) => {
  try {
    const user = await getCurrentUser(req.user!.id);
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

export default router;
