import { Router, Response, Request, urlencoded } from 'express';
import { z } from 'zod';
import { validateBody } from '../../middleware/validate.js';
import { socialStartRateLimit, socialCallbackRateLimit } from '../../middleware/rateLimit.js';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import * as socialService from './social.service.js';
import { issueMobileAuthCode, exchangeMobileAuthCode } from './mobileAuthCode.service.js';
import { handleFacebookDeauthorizeCallback } from './facebookDeauthorize.service.js';
import { config } from '../../config/index.js';
import { createAuthorizationCode } from '../oauth/oauth.service.js';

const router = Router();
const metaFormBody = urlencoded({ extended: false });

type SocialStateForContinuation = {
  provider?: socialService.SocialAuthorizationTransaction['provider'] | null;
  authTransactionId?: string | null;
  redirectContext?: Record<string, string | undefined>;
};

type SocialContinuationResult =
  | { kind: 'NONE' }
  | { kind: 'REDIRECT'; location: string }
  | { kind: 'ERROR'; status: number; body: Record<string, unknown> };

function authenticatedUserId(result: socialService.SocialCallbackResult) {
  return result.kind === 'LOGIN' || result.kind === 'AUTHENTICATED'
    ? result.user.id
    : null;
}

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

function redirectBrowserClientError(
  res: Response,
  redirectUri: string,
  error: string,
  state?: string,
) {
  const redirect = new URL(redirectUri);
  redirect.searchParams.set('error', error);
  if (state) redirect.searchParams.set('state', state);
  res.redirect(redirect.toString());
}

export async function completeSocialAuthorizationContinuation(input: {
  result: socialService.SocialCallbackResult;
  statePayload: SocialStateForContinuation;
  req: Request;
  consumeTransaction?: typeof socialService.consumeSocialAuthorizationTransaction;
  createAuthorizationCodeFn?: typeof createAuthorizationCode;
  issueMobileAuthCodeFn?: typeof issueMobileAuthCode;
}): Promise<SocialContinuationResult> {
  if (!input.statePayload.authTransactionId) return { kind: 'NONE' };

  const consumeTransaction = input.consumeTransaction ?? socialService.consumeSocialAuthorizationTransaction;
  const tx = await consumeTransaction(input.statePayload.authTransactionId);
  if (!tx) {
    console.warn('Social authorization continuation failed', {
      reason: 'AUTH_TRANSACTION_NOT_FOUND',
      transactionId: input.statePayload.authTransactionId,
    });
    return {
      kind: 'ERROR',
      status: 400,
      body: { success: false, code: 'INVALID_STATE', message: 'The authentication request has expired. Please return to the application and try again.' },
    };
  }

  if (input.statePayload.provider && tx.provider !== input.statePayload.provider) {
    console.warn('Social authorization continuation failed', {
      reason: 'PROVIDER_MISMATCH',
      expectedProvider: tx.provider,
      stateProvider: input.statePayload.provider,
      transactionId: input.statePayload.authTransactionId,
      clientId: tx.clientId,
    });
    return {
      kind: 'ERROR',
      status: 400,
      body: { success: false, code: 'INVALID_STATE', message: 'The authentication request is invalid. Please return to the application and try again.' },
    };
  }

  const userId = authenticatedUserId(input.result);
  if (!userId) {
    console.warn('Social authorization continuation failed', {
      reason: input.result.kind === 'EMAIL_REQUIRED' ? 'SOCIAL_EMAIL_REQUIRED' : 'USER_NOT_AUTHENTICATED',
      provider: tx.provider,
      transactionId: input.statePayload.authTransactionId,
      clientId: tx.clientId,
    });
    return {
      kind: 'ERROR',
      status: 400,
      body: { success: false, code: 'AUTHORIZATION_CONTINUATION_FAILED', message: 'Social sign-in could not complete this authorization request.' },
    };
  }

  if (tx.mode === 'mobile') {
    if (input.result.kind !== 'LOGIN') {
      return {
        kind: 'ERROR',
        status: 400,
        body: { success: false, code: 'AUTHORIZATION_CONTINUATION_FAILED', message: 'Mobile social sign-in could not complete this authorization request.' },
      };
    }
    if (!tx.codeChallenge) {
      const redirect = `${tx.redirectUri}?${new URLSearchParams({ error: 'PKCE_REQUIRED', ...(tx.appState ? { state: tx.appState } : {}) }).toString()}`;
      return { kind: 'REDIRECT', location: redirect };
    }
    const issueMobileCode = input.issueMobileAuthCodeFn ?? issueMobileAuthCode;
    const code = await issueMobileCode({
      clientDbId: tx.clientDbId,
      redirectUri: tx.redirectUri,
      codeChallenge: tx.codeChallenge,
      session: {
        accessToken: input.result.accessToken,
        refreshToken: input.result.refreshToken,
        expiresIn: input.result.expiresIn,
      },
    });
    const redirect = `${tx.redirectUri}?${new URLSearchParams({ code, ...(tx.appState ? { state: tx.appState } : {}) }).toString()}`;
    return { kind: 'REDIRECT', location: redirect };
  }

  const createCode = input.createAuthorizationCodeFn ?? createAuthorizationCode;
  const codeResult = await createCode({
    clientId: tx.clientId,
    redirectUri: tx.redirectUri,
    scopes: tx.scopes,
    state: tx.state,
    codeChallenge: tx.codeChallenge,
    codeChallengeMethod: tx.codeChallengeMethod,
    nonce: tx.nonce,
    userId,
    req: input.req,
  });
  const redirect = new URL(tx.redirectUri);
  redirect.searchParams.set('code', codeResult.code);
  if (codeResult.state) redirect.searchParams.set('state', codeResult.state);
  console.info('Social authorization continuation completed', {
    provider: tx.provider,
    clientId: tx.clientId,
    transactionId: input.statePayload.authTransactionId,
    redirectHost: redirect.host,
    redirectPath: redirect.pathname,
  });
  return { kind: 'REDIRECT', location: redirect.toString() };
}

async function redirectProviderErrorFromState(
  statePayload: SocialStateForContinuation,
  error: string,
) {
  if (statePayload.authTransactionId) {
    const tx = await socialService.consumeSocialAuthorizationTransaction(statePayload.authTransactionId);
    if (!tx) return null;
    const redirect = new URL(tx.redirectUri);
    redirect.searchParams.set('error', error);
    if (tx.state) redirect.searchParams.set('state', tx.state);
    return redirect.toString();
  }
  return null;
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
    const browserRedirectUri = statePayload.redirectContext?.redirect_uri;
    if (parsed.error) {
      const transactionErrorRedirect = await redirectProviderErrorFromState(statePayload, parsed.error);
      if (transactionErrorRedirect) {
        res.redirect(transactionErrorRedirect);
        return;
      }
      if (browserRedirectUri) {
        redirectBrowserClientError(res, browserRedirectUri, parsed.error, statePayload.redirectContext?.state);
        return;
      }
      if (isAdminTest && statePayload.nonce) {
        const adminTestContext = await socialService.consumeAdminProviderTestState(statePayload.nonce);
        if (!adminTestContext) {
          res.status(400).json({ success: false, code: 'INVALID_STATE', message: 'Invalid or expired state.' });
          return;
        }
        const message = parsed.error_description || parsed.error_reason || parsed.error || 'Facebook rejected the test login.';
        await socialService.recordProviderTestFailure({
          rowId: adminTestContext.providerConfigId,
          errorMessage: message,
          req,
          actorId: adminTestContext.adminId ?? undefined,
        });
        const redirectTo = new URL(adminTestContext.returnTo ?? `${config.ADMIN_PANEL_ORIGIN.replace(/\/$/, '')}/authentication/social-providers`);
        redirectTo.searchParams.set('provider', String(adminTestContext.provider ?? statePayload.provider ?? req.params.provider).toUpperCase());
        redirectTo.searchParams.set('test', 'failure');
        redirectTo.searchParams.set('message', message.slice(0, 160));
        res.redirect(redirectTo.toString());
        return;
      }
      res.status(400).json({ success: false, code: 'OAUTH_ERROR', message: parsed.error_description || parsed.error || 'OAuth provider rejected the request.' });
      return;
    }
    const result = await socialService.handleCallback(req.params.provider, parsed.code!, parsed.state, req);

    const continuation = await completeSocialAuthorizationContinuation({ result, statePayload, req });
    if (continuation.kind === 'REDIRECT') {
      res.redirect(continuation.location);
      return;
    }
    if (continuation.kind === 'ERROR') {
      res.status(continuation.status).json(continuation.body);
      return;
    }

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

    if (result.kind === 'LOGIN' && browserRedirectUri) {
      const redirectContext = statePayload.redirectContext ?? {};
      const clientId = redirectContext.client_id;
      if (!clientId) {
        res.status(400).json({ success: false, code: 'INVALID_STATE', message: 'Missing client_id in state.' });
        return;
      }
      const codeResult = await createAuthorizationCode({
        clientId,
        redirectUri: browserRedirectUri,
        scopes: (redirectContext.scope ?? 'openid profile email').split(' ').filter(Boolean),
        state: redirectContext.state,
        codeChallenge: redirectContext.code_challenge,
        codeChallengeMethod: redirectContext.code_challenge_method,
        nonce: redirectContext.nonce,
        userId: result.user.id,
        req,
      });
      const redirect = new URL(browserRedirectUri);
      redirect.searchParams.set('code', codeResult.code);
      if (codeResult.state) redirect.searchParams.set('state', codeResult.state);
      res.redirect(redirect.toString());
      return;
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
    if (result.kind === 'LOGIN') {
      res.json({ success: true, accessToken: result.accessToken, refreshToken: result.refreshToken, expiresIn: result.expiresIn, user: result.user });
      return;
    }
    res.status(400).json({ success: false, code: 'AUTHORIZATION_CONTINUATION_FAILED', message: 'Social sign-in could not complete this request.' });
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
