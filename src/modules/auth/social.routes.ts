import { Router, urlencoded } from 'express';
import { z } from 'zod';
import { validateBody } from '../../middleware/validate.js';
import { socialStartRateLimit, socialCallbackRateLimit } from '../../middleware/rateLimit.js';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import * as socialService from './social.service.js';
import { issueMobileAuthCode, exchangeMobileAuthCode } from './mobileAuthCode.service.js';
import { handleFacebookDeauthorizeCallback } from './facebookDeauthorize.service.js';
import { config } from '../../config/index.js';

const router = Router();
const metaFormBody = urlencoded({ extended: false });

export function parseSocialCallbackQuery(query: unknown) {
  const parsed = z.object({
    code: z.string().min(1).optional(),
    state: z.string().min(1),
    error: z.string().min(1).optional(),
    error_description: z.string().min(1).optional(),
    error_reason: z.string().min(1).optional(),
  }).safeParse(query);
  if (!parsed.success) return null;
  if (!parsed.data.code && !parsed.data.error) return null;
  return parsed.success ? parsed.data : null;
}

// ─── Mobile PKCE token exchange ──────────────────────────────────────────────
// POST /auth/social/mobile/token — exchanges the single-use authorization
// code from the mobile callback redirect for the session tokens. The code is
// bound to the client, redirect URI, and S256 code challenge; the verifier
// proves this caller started the flow. Neither the code nor the tokens are
// ever logged.
const mobileTokenSchema = z.object({
  code: z.string().min(16),
  codeVerifier: z.string().min(43).max(128),
  clientId: z.string().min(1),
  redirectUri: z.string().min(1),
});

router.post('/mobile/token', socialCallbackRateLimit, validateBody(mobileTokenSchema), async (req, res, next) => {
  try {
    const session = await exchangeMobileAuthCode({
      code: req.body.code,
      codeVerifier: req.body.codeVerifier,
      clientId: req.body.clientId,
      redirectUri: req.body.redirectUri,
    });
    res.json({ success: true, ...session });
  } catch (err) {
    next(err);
  }
});

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

// Explicit account linking: attach a social identity to the currently
// logged-in user (supports "add Google to my existing password account",
// etc.) rather than only the implicit login-time auto-link.
router.get('/:provider/link/start', authGuard, socialStartRateLimit, async (req: AuthenticatedRequest, res, next) => {
  try {
    const url = await socialService.getStartRedirect(req.params.provider, req, { linkUserId: req.user!.id });
    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

router.post(
  '/facebook/deauthorize',
  metaFormBody,
  socialCallbackRateLimit,
  validateBody(z.object({
    signed_request: z.string().min(1).optional(),
    signedRequest: z.string().min(1).optional(),
  }).refine((value) => Boolean(value.signed_request || value.signedRequest), {
    message: 'signed_request is required.',
  })),
  async (req, res, next) => {
    try {
      const signedRequest = req.body.signed_request ?? req.body.signedRequest;
      await handleFacebookDeauthorizeCallback({ signedRequest, req });
      res.status(200).send('OK');
    } catch (err) {
      next(err);
    }
  },
);

router.get('/:provider/callback', socialCallbackRateLimit, async (req, res, next) => {
  try {
    const parsed = parseSocialCallbackQuery(req.query);
    if (!parsed) {
      res.status(400).json({ success: false, message: 'Missing code or state.' });
      return;
    }
    const statePayload = socialService.verifySocialState(parsed.state);
    const isAdminTest = statePayload.purpose === 'ADMIN_PROVIDER_TEST';
    if (parsed.error) {
      if (isAdminTest && statePayload.providerConfigId) {
        const message = parsed.error_description || parsed.error_reason || parsed.error || 'Facebook rejected the test login.';
        await socialService.recordProviderTestFailure({
          rowId: statePayload.providerConfigId,
          errorMessage: message,
          req,
          actorId: statePayload.adminId ?? undefined,
        });
        const redirectTo = new URL(statePayload.returnTo ?? `${config.ADMIN_PANEL_ORIGIN.replace(/\/$/, '')}/authentication/social-providers`);
        redirectTo.searchParams.set('provider', String(statePayload.provider ?? req.params.provider).toUpperCase());
        redirectTo.searchParams.set('test', 'failure');
        redirectTo.searchParams.set('message', message.slice(0, 160));
        res.redirect(redirectTo.toString());
        return;
      }
      res.status(400).json({ success: false, code: 'OAUTH_ERROR', message: parsed.error_description || parsed.error || 'OAuth provider rejected the request.' });
      return;
    }
    const result = await socialService.handleCallback(req.params.provider, parsed.code!, parsed.state, req);

    // Mobile system-browser flow (flutter_web_auth_2): when the signed state
    // carries a registered custom-scheme redirect for the requesting
    // AuthClient, hand back a short-lived single-use AUTHORIZATION CODE —
    // never the tokens themselves. The app exchanges it at
    // POST /auth/mobile/token with its PKCE code_verifier. Web/JSON callers
    // (BPA today) get the pre-existing responses unchanged.
    const mobile = await socialService.resolveMobileRedirect(parsed.state);
    if (mobile) {
      const echoState = (extra: Record<string, string>) =>
        new URLSearchParams({ ...extra, ...(mobile.appState ? { state: mobile.appState } : {}) }).toString();

      if (result.kind === 'LOGIN') {
        if (!mobile.codeChallenge) {
          // No PKCE challenge was supplied on /start — refuse to hand any
          // credential material to a custom scheme without it.
          res.redirect(`${mobile.redirectUri}?${echoState({ error: 'PKCE_REQUIRED' })}`);
          return;
        }
        const code = await issueMobileAuthCode({
          clientDbId: mobile.clientDbId,
          redirectUri: mobile.redirectUri,
          codeChallenge: mobile.codeChallenge,
          session: {
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
            expiresIn: result.expiresIn,
          },
        });
        res.redirect(`${mobile.redirectUri}?${echoState({ code })}`);
        return;
      }
      if (result.kind === 'EMAIL_REQUIRED') {
        res.redirect(`${mobile.redirectUri}?${echoState({
          error: 'SOCIAL_EMAIL_REQUIRED',
          completionToken: result.completionToken,
          provider: String(result.provider),
        })}`);
        return;
      }
      if (result.kind === 'LINKED') {
        res.redirect(`${mobile.redirectUri}?${echoState({ linked: 'true', provider: String(result.provider) })}`);
        return;
      }
    }

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
    if (result.kind === 'LINKED') {
      res.json({ success: true, linked: true, provider: result.provider });
      return;
    }
    if (result.kind === 'ADMIN_TEST_COMPLETE') {
      res.redirect(result.redirectUrl);
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
