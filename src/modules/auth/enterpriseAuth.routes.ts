// System-browser enterprise OIDC login routes (mobile completion via the
// same single-use PKCE authorization-code contract as social login).
import { Router } from 'express';
import { z } from 'zod';
import { socialStartRateLimit, socialCallbackRateLimit } from '../../middleware/rateLimit.js';
import { getEnterpriseStartRedirect, verifyEnterpriseCallback } from './enterpriseBrowser.service.js';
import { oidcLoginOrCreate } from './identityLogin.service.js';
import { resolveMobileRedirect } from './social.service.js';
import { issueMobileAuthCode } from './mobileAuthCode.service.js';

const router = Router();

// GET /auth/enterprise/:orgSlug/start — redirects the system browser to the
// org's IdP (auth code + PKCE + nonce). SAML orgs get a typed
// ENTERPRISE_PROVIDER_UNSUPPORTED (501), never a fake flow.
router.get('/:orgSlug/start', socialStartRateLimit, async (req, res, next) => {
  try {
    const url = await getEnterpriseStartRedirect(req.params.orgSlug, req);
    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

// GET /auth/enterprise/callback — IdP redirect target. Exchanges the code
// server-side (client secret never leaves this API), verifies the id_token
// (JWKS/iss/aud/exp/nonce), resolves the Central Auth identity, then hands
// the mobile app a single-use PKCE-bound code. Non-mobile callers get JSON.
router.get('/callback', socialCallbackRateLimit, async (req, res, next) => {
  try {
    const parsed = z.object({ code: z.string().min(1), state: z.string().min(1) }).safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ success: false, message: 'Missing code or state.' });
      return;
    }
    const verified = await verifyEnterpriseCallback(parsed.data.code, parsed.data.state);
    const result = await oidcLoginOrCreate(verified.profile, verified.appClientId, req);

    const mobile = await resolveMobileRedirect(parsed.data.state);
    if (mobile) {
      const echoState = (extra: Record<string, string>) =>
        new URLSearchParams({ ...extra, ...(mobile.appState ? { state: mobile.appState } : {}) }).toString();

      if (result.kind === 'LOGIN') {
        if (!mobile.codeChallenge) {
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
      if (result.kind === 'NEEDS_PROFILE_COMPLETION') {
        res.redirect(`${mobile.redirectUri}?${echoState({
          error: 'NEEDS_PROFILE_COMPLETION',
          missingFields: result.missingFields.join(','),
        })}`);
        return;
      }
    }

    if (result.kind === 'NEEDS_PROFILE_COMPLETION') {
      res.status(409).json({ success: false, code: 'NEEDS_PROFILE_COMPLETION', missingFields: result.missingFields, message: result.message });
      return;
    }
    res.json({ success: true, accessToken: result.accessToken, refreshToken: result.refreshToken, expiresIn: result.expiresIn, user: result.user });
  } catch (err) {
    next(err);
  }
});

export default router;
