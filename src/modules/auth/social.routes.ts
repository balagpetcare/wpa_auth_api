import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '../../middleware/validate.js';
import { socialStartRateLimit, socialCallbackRateLimit } from '../../middleware/rateLimit.js';
import * as socialService from './social.service.js';

const router = Router();

router.get('/providers', async (_req, res, next) => {
  try {
    const providers = await socialService.listPublicProviders();
    res.json({ success: true, main: providers.main, more: providers.more });
  } catch (err) {
    next(err);
  }
});

router.get('/:provider/start', socialStartRateLimit, async (req, res, next) => {
  try {
    const url = await socialService.getStartRedirect(req.params.provider, req);
    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

router.get('/:provider/callback', socialCallbackRateLimit, async (req, res, next) => {
  try {
    const parsed = z.object({ code: z.string().min(1), state: z.string().min(1) }).safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ success: false, message: 'Missing code or state.' });
      return;
    }
    const result = await socialService.handleCallback(req.params.provider, parsed.data.code, parsed.data.state, req);
    if (result.kind === 'EMAIL_REQUIRED') {
      const completionUrl = new URL(`${req.protocol}://${req.get('host')}/auth/social/complete-email`);
      completionUrl.searchParams.set('token', result.completionToken);
      if (req.accepts(['html', 'json']) === 'html') {
        res.redirect(completionUrl.toString());
        return;
      }
      res.status(409).json({ code: 'SOCIAL_EMAIL_REQUIRED', message: result.message, provider: result.provider, completionToken: result.completionToken });
      return;
    }
    res.json({ success: true, accessToken: result.accessToken, refreshToken: result.refreshToken, expiresIn: result.expiresIn, user: result.user });
  } catch (err) {
    next(err);
  }
});

router.post('/complete-email/request', validateBody(z.object({ completionToken: z.string().min(1), email: z.string().email() })), async (req, res, next) => {
  try {
    const data = await socialService.requestSocialEmailCompletion(req.body.completionToken, req.body.email, req);
    res.json({ success: true, completionToken: data.completionToken });
  } catch (err) {
    next(err);
  }
});

router.post('/complete-email/confirm', validateBody(z.object({ completionToken: z.string().min(1), email: z.string().email(), code: z.string().min(1) })), async (req, res, next) => {
  try {
    const data = await socialService.confirmSocialEmailCompletion(req.body.completionToken, req.body.email, req.body.code, req);
    res.json({ success: true, message: data.message });
  } catch (err) {
    next(err);
  }
});

export default router;
