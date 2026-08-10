import { Router } from 'express';
import { z } from 'zod';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import { validateBody } from '../../middleware/validate.js';
import { getCurrentUser, updateCurrentUserProfile } from '../auth/auth.service.js';

const router = Router();

// Central Auth owns: name parts and date of birth (see
// updateCurrentUserProfile in auth.service.ts, which is the single source
// of truth for this allowlist and already enforces the
// EMAIL_CHANGE_REQUIRES_VERIFICATION / PHONE_CHANGE_REQUIRES_VERIFICATION
// guards). This route is a thin alias delegating to that same service —
// it must never duplicate the update logic or write to Prisma directly,
// so the two mount points (/auth/me and /users/me) can never drift apart
// or offer a bypass of the identity-change guards.
const updateUsersMeSchema = z.object({
  displayName: z.string().max(64).nullable().optional(),
  firstName: z.string().max(64).nullable().optional(),
  lastName: z.string().max(64).nullable().optional(),
  dateOfBirth: z.string().nullable().optional(),
});

router.get('/me', authGuard, async (req: AuthenticatedRequest, res, next) => {
  try {
    const user = await getCurrentUser(req.user!.id);
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

router.patch(
  '/me',
  authGuard,
  validateBody(updateUsersMeSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const user = await updateCurrentUserProfile(req.user!.id, req.body, req);
      res.json({ success: true, user });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
