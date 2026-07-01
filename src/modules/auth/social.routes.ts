import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '../../middleware/validate.js';
import * as socialService from './social.service.js';
import { prisma } from '../../lib/db.js';
import { socialStartRateLimit, socialCallbackRateLimit, socialMobileRateLimit } from '../../middleware/rateLimit.js';

const router = Router();

// GET /auth/social/providers
router.get('/providers', async (req, res, next) => {
  try {
    const settings = await prisma.socialProviderSetting.findMany({
      where: { enabled: true },
      orderBy: { displayOrder: 'asc' },
      select: { provider: true, displayName: true, icon: true },
    });
    res.json({ success: true, providers: settings });
  } catch (err) {
    next(err);
  }
});

// GET /auth/social/:provider/start
router.get('/:provider/start', socialStartRateLimit, async (req, res, next) => {
  try {
    const { provider } = req.params;
    const clientId = req.query.client_id as string;
    const redirectUri = req.query.redirect_uri as string;

    if (!clientId || !redirectUri) {
      res.status(400).json({ success: false, message: 'client_id and redirect_uri are required' });
      return;
    }

    const origin = req.headers.origin as string | undefined;
    const url = await socialService.getSocialStartUrl(provider, clientId, redirectUri, origin);
    res.json({ success: true, url });
  } catch (err) {
    next(err);
  }
});

// GET /auth/social/:provider/callback
router.get('/:provider/callback', socialCallbackRateLimit, async (req, res, next) => {
  try {
    const { provider } = req.params;
    const code = req.query.code as string;
    const state = req.query.state as string;
    const error = req.query.error as string;

    if (error) {
      res.status(400).json({ success: false, message: `Provider returned error: ${error}` });
      return;
    }

    if (!code || !state) {
      res.status(400).json({ success: false, message: 'code and state are required' });
      return;
    }

    const result = await socialService.handleSocialCallback(provider, code, state, req);
    if ('url' in result) {
      res.redirect(result.url as string);
    } else {
      res.json(result);
    }
  } catch (err) {
    next(err);
  }
});

// POST /auth/social/:provider/mobile
router.post('/:provider/mobile', socialMobileRateLimit, validateBody(z.object({
  token: z.string().min(1),
  client_id: z.string().min(1),
})), async (req, res, next) => {
  try {
    const { provider } = req.params;
    const { token, client_id } = req.body;
    
    const result = await socialService.mobileSocialLogin(provider, token, client_id, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

export default router;
