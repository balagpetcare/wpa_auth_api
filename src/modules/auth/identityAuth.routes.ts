import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '../../middleware/validate.js';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import { enterpriseRateLimit } from '../../lib/antiAbuse.js';
import { AppError, ErrorCodes } from '../../lib/errors.js';
import { getBootstrapConfig } from './bootstrap.service.js';
import { requestLoginOtp, verifyLoginOtp } from './otp.service.js';
import { loginWithPhonePassword, setPasswordForCurrentUser, oidcLoginOrCreate, linkIdentityToExistingUser, listLinkedIdentities, unlinkIdentity } from './identityLogin.service.js';
import { OAuthProvider } from '@prisma/client';
import { verifyGoogleIdToken } from './identity-providers/google.js';
import { verifyFacebookAccessToken } from './identity-providers/facebook.js';
import { verifyAppleIdToken } from './identity-providers/apple.js';
import { verifyMicrosoftIdToken } from './identity-providers/microsoft.js';
import { verifyEnterpriseOidcIdToken } from './identity-providers/enterprise.js';
import type { NormalizedIdentityProfile } from './identity-providers/types.js';

const router = Router();

// ─── Bootstrap ───────────────────────────────────────────────────────────────

router.get('/bootstrap', async (req, res, next) => {
  try {
    const clientId = typeof req.query.clientId === 'string' ? req.query.clientId : undefined;
    const data = await getBootstrapConfig(clientId);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// ─── OTP passwordless login ──────────────────────────────────────────────────

const otpRequestSchema = z.object({
  channel: z.enum(['email', 'phone', 'whatsapp']),
  recipient: z.string().min(3),
  clientId: z.string().optional(),
});

router.post(
  '/otp/request',
  enterpriseRateLimit({
    route: 'auth-otp-request',
    windowMs: 15 * 60 * 1000,
    max: 5,
    identifierFrom: (req) => `${req.body?.channel ?? ''}:${req.body?.recipient ?? ''}`,
    threat: 'OTP_ABUSE_DETECTED',
    blockScope: 'identifier',
  }),
  validateBody(otpRequestSchema),
  async (req, res, next) => {
    try {
      const result = await requestLoginOtp(req.body, req);
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

const otpVerifySchema = z.object({
  channel: z.enum(['email', 'phone']),
  recipient: z.string().min(3),
  code: z.string().min(4).max(10),
  clientId: z.string().optional(),
});

router.post(
  '/otp/verify',
  enterpriseRateLimit({
    route: 'auth-otp-verify',
    windowMs: 15 * 60 * 1000,
    max: 10,
    identifierFrom: (req) => `${req.body?.channel ?? ''}:${req.body?.recipient ?? ''}`,
    threat: 'OTP_ABUSE_DETECTED',
    blockScope: 'identifier',
  }),
  validateBody(otpVerifySchema),
  async (req, res, next) => {
    try {
      const result = await verifyLoginOtp(req.body, req);
      res.json({ success: true, ...result });
    } catch (err) {
      next(err);
    }
  },
);

// ─── Phone + password login ──────────────────────────────────────────────────

const phoneLoginSchema = z.object({
  phone: z.string().min(7),
  password: z.string().min(1),
  clientId: z.string().optional(),
});

router.post(
  '/login/phone',
  enterpriseRateLimit({
    route: 'auth-login-phone',
    windowMs: 15 * 60 * 1000,
    max: 10,
    identifierFrom: (req) => `${req.body?.phone ?? ''}:${req.ip ?? ''}`,
    threat: 'BOT_TRAFFIC_SPIKE',
    blockScope: 'identifier',
  }),
  validateBody(phoneLoginSchema),
  async (req, res, next) => {
    try {
      const result = await loginWithPhonePassword(req.body, req);
      res.json({ success: true, ...result });
    } catch (err) {
      next(err);
    }
  },
);

// ─── Set password (social/OIDC-only accounts) ───────────────────────────────

const setPasswordSchema = z.object({
  password: z.string().min(8),
});

router.post('/password/set', authGuard, validateBody(setPasswordSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await setPasswordForCurrentUser(req.user!.id, req.body.password, req);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// ─── Identity-provider (Google/Facebook/Apple/Microsoft/Enterprise) login ───

const providerTokenSchema = z.object({
  idToken: z.string().min(10).optional(),
  accessToken: z.string().min(10).optional(),
  nonce: z.string().optional(),
  clientId: z.string().optional(),
}).refine((d) => d.idToken || d.accessToken, { message: 'idToken or accessToken is required.' });

async function resolveProfile(provider: string, orgSlug: string | undefined, body: z.infer<typeof providerTokenSchema>): Promise<NormalizedIdentityProfile> {
  switch (provider) {
    case 'google':
      if (!body.idToken) throw new AppError('idToken is required for Google.', 'VALIDATION_ERROR', 400);
      return verifyGoogleIdToken(body.idToken);
    case 'facebook':
      if (!body.accessToken) throw new AppError('accessToken is required for Facebook.', 'VALIDATION_ERROR', 400);
      return verifyFacebookAccessToken(body.accessToken);
    case 'apple':
      if (!body.idToken) throw new AppError('idToken is required for Apple.', 'VALIDATION_ERROR', 400);
      return verifyAppleIdToken(body.idToken, { nonce: body.nonce });
    case 'microsoft':
      if (!body.idToken) throw new AppError('idToken is required for Microsoft.', 'VALIDATION_ERROR', 400);
      return verifyMicrosoftIdToken(body.idToken, { nonce: body.nonce });
    case 'enterprise':
      if (!orgSlug) throw new AppError('orgSlug is required for enterprise login.', 'VALIDATION_ERROR', 400);
      if (!body.idToken) throw new AppError('idToken is required for enterprise login.', 'VALIDATION_ERROR', 400);
      return verifyEnterpriseOidcIdToken(orgSlug, body.idToken, { nonce: body.nonce });
    default:
      throw new AppError('Unsupported identity provider.', ErrorCodes.PROVIDER_DISABLED, 400);
  }
}

router.post('/identity/:provider', enterpriseRateLimit({
  route: 'auth-identity-login',
  windowMs: 15 * 60 * 1000,
  max: 20,
  identifierFrom: (req) => `${req.params.provider}:${req.ip ?? ''}`,
}), validateBody(providerTokenSchema), async (req, res, next) => {
  try {
    const orgSlug = typeof req.query.org === 'string' ? req.query.org : undefined;
    const profile = await resolveProfile(req.params.provider, orgSlug, req.body);
    const result = await oidcLoginOrCreate(profile, req.body.clientId, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// ─── Link an additional provider to the current authenticated user ─────────

router.post('/identity/:provider/link', authGuard, validateBody(providerTokenSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    const orgSlug = typeof req.query.org === 'string' ? req.query.org : undefined;
    const profile = await resolveProfile(req.params.provider, orgSlug, req.body);
    const result = await linkIdentityToExistingUser(profile, req.user!.id, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// ─── Read-only linked-identities list (account / linking-management screen) ──
// Additive, safe surface: returns only display fields (provider, email,
// verified flag, linked/last-login dates) — never provider tokens. Unblocks
// the Furtail/BPA "linked providers" screen without exposing secrets.
router.get('/identities', authGuard, async (req: AuthenticatedRequest, res, next) => {
  try {
    const identities = await listLinkedIdentities(req.user!.id);
    res.json({ success: true, identities });
  } catch (err) {
    next(err);
  }
});

// ─── Unlink an external identity ─────────────────────────────────────────────
// Refuses (409 LAST_LOGIN_METHOD) if it would remove the only sign-in method.
router.delete('/identity/:provider', authGuard, async (req: AuthenticatedRequest, res, next) => {
  try {
    const providerRaw = String(req.params.provider || '').toUpperCase();
    if (!(providerRaw in OAuthProvider)) {
      throw new AppError('Unsupported identity provider.', ErrorCodes.PROVIDER_DISABLED, 400);
    }
    const result = await unlinkIdentity(req.user!.id, providerRaw as OAuthProvider, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

export default router;
