import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '../../middleware/validate.js';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import * as oauthService from './oauth.service.js';
import { AppError } from '../../lib/errors.js';
import { enterpriseRateLimit } from '../../lib/antiAbuse.js';

const router = Router();

// ─── GET /oauth/authorize ────────────────────────────────────────────────────
// The user must already be authenticated (access token in header).
// The client app redirects the user's browser here after they log in.
// Returns { code, state } — client app exchanges it at /oauth/token.

const authorizeSchema = z.object({
  response_type: z.literal('code'),
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  scope: z.string().default('openid'),
  state: z.string().optional(),
  code_challenge: z.string().optional(),
  code_challenge_method: z.enum(['S256', 'plain']).optional(),
  // Phase 2.5 (docs/phase-2-5-public-auth-rs256-oidc.md): OIDC nonce, echoed
  // back verbatim in the id_token to let the client detect replay.
  nonce: z.string().optional(),
});

// Phase 2 fix (docs/phase-2-core-identity-admin-modules.md): previously this
// always called createAuthorizationCode() directly, so every client —
// including THIRD_PARTY_APP ones — was auto-approved with no consent step.
// Now delegates to startAuthorization(), which only auto-approves
// FIRST_PARTY_APP/SERVICE clients (unchanged behavior) and returns a
// requiresConsent ticket for THIRD_PARTY_APP clients instead of a code.
router.get('/authorize', enterpriseRateLimit({ route: 'oauth-authorize', windowMs: 15 * 60 * 1000, max: 20, identifierFrom: (req) => `${req.query.client_id ?? ''}:${req.ip ?? ''}`, threat: 'SUSPICIOUS_ACTIVITY_BLOCKED' }), authGuard, async (req: AuthenticatedRequest, res, next) => {
  try {
    const parsed = authorizeSchema.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ success: false, message: 'Invalid authorize request.', code: 'INVALID_REQUEST', errors: parsed.error.issues });
      return;
    }

    const q = parsed.data;
    const scopes = q.scope.split(' ').filter(Boolean);

    const result = await oauthService.startAuthorization({
      clientId: q.client_id,
      redirectUri: q.redirect_uri,
      scopes,
      state: q.state,
      codeChallenge: q.code_challenge,
      codeChallengeMethod: q.code_challenge_method,
      nonce: q.nonce,
      userId: req.user!.id,
      req,
    });

    // In a real browser flow the server would redirect to redirect_uri?code=...&state=...
    // For API-first first-party apps, return JSON and let the client handle the redirect.
    // requiresConsent=true means the client is THIRD_PARTY_APP — the caller
    // (admin panel's /oauth/consent page) must render the consent screen and
    // call POST /oauth/consent with the returned consentTicket before a code
    // is issued.
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// ─── POST /oauth/consent ─────────────────────────────────────────────────────
// Resolves a pending third-party consent ticket from GET /oauth/authorize.
const consentSchema = z.object({
  consentTicket: z.string().min(1),
  decision: z.enum(['approve', 'deny']),
});

router.post('/consent', enterpriseRateLimit({ route: 'oauth-consent', windowMs: 15 * 60 * 1000, max: 20, identifierFrom: (req) => `${req.body?.consentTicket ?? ''}:${req.ip ?? ''}`, threat: 'SUSPICIOUS_ACTIVITY_BLOCKED' }), authGuard, validateBody(consentSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await oauthService.resolveConsent({
      consentTicket: req.body.consentTicket,
      decision: req.body.decision,
      userId: req.user!.id,
      req,
    });
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// ─── POST /oauth/token ───────────────────────────────────────────────────────

const tokenBaseSchema = z.object({
  grant_type: z.enum(['authorization_code', 'refresh_token', 'client_credentials']),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
});

const authCodeSchema = tokenBaseSchema.extend({
  grant_type: z.literal('authorization_code'),
  code: z.string().min(1),
  redirect_uri: z.string().url(),
  code_verifier: z.string().optional(),
});

const refreshSchema = tokenBaseSchema.extend({
  grant_type: z.literal('refresh_token'),
  refresh_token: z.string().min(1),
  scope: z.string().optional(),
});

const clientCredsSchema = tokenBaseSchema.extend({
  grant_type: z.literal('client_credentials'),
  client_secret: z.string().min(1),
  scope: z.string().optional(),
});

router.post('/token', enterpriseRateLimit({ route: 'oauth-token', windowMs: 15 * 60 * 1000, max: 50, identifierFrom: (req) => `${req.body?.client_id ?? ''}:${req.ip ?? ''}`, threat: 'OAUTH_CLIENT_SECRET_ABUSE' }), async (req, res, next) => {
  try {
    const { grant_type } = req.body;

    if (grant_type === 'authorization_code') {
      const parsed = authCodeSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ success: false, message: 'Invalid token request.', code: 'INVALID_REQUEST', errors: parsed.error.issues });
        return;
      }
      const d = parsed.data;
      const result = await oauthService.exchangeAuthorizationCode({
        code: d.code,
        clientId: d.client_id,
        clientSecret: d.client_secret,
        redirectUri: d.redirect_uri,
        codeVerifier: d.code_verifier,
        req,
      });
      res.json(result);
      return;
    }

    if (grant_type === 'refresh_token') {
      const parsed = refreshSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ success: false, message: 'Invalid token request.', code: 'INVALID_REQUEST', errors: parsed.error.issues });
        return;
      }
      const d = parsed.data;
      const result = await oauthService.exchangeRefreshToken({
        refreshToken: d.refresh_token,
        clientId: d.client_id,
        clientSecret: d.client_secret,
        scopes: d.scope?.split(' ').filter(Boolean),
        req,
      });
      res.json(result);
      return;
    }

    if (grant_type === 'client_credentials') {
      const parsed = clientCredsSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ success: false, message: 'Invalid token request.', code: 'INVALID_REQUEST', errors: parsed.error.issues });
        return;
      }
      const d = parsed.data;
      const result = await oauthService.clientCredentials({
        clientId: d.client_id,
        clientSecret: d.client_secret,
        scopes: d.scope?.split(' ').filter(Boolean) ?? [],
        req,
      });
      res.json(result);
      return;
    }

    throw new AppError(`Unsupported grant_type: ${grant_type}`, 'UNSUPPORTED_GRANT_TYPE', 400);
  } catch (err) {
    next(err);
  }
});

// ─── GET /oauth/userinfo ─────────────────────────────────────────────────────

router.get('/userinfo', authGuard, async (req: AuthenticatedRequest, res, next) => {
  try {
    const info = await oauthService.getUserInfo(req.user!.id);
    res.json(info);
  } catch (err) {
    next(err);
  }
});

// ─── GET /oauth/jwks ─────────────────────────────────────────────────────────

router.get('/jwks', (_req, res) => {
  res.json(oauthService.getJwks());
});

// ─── POST /oauth/introspect ──────────────────────────────────────────────────

router.post('/introspect', enterpriseRateLimit({ route: 'oauth-introspect', windowMs: 15 * 60 * 1000, max: 100, identifierFrom: (req) => `${req.body?.client_id ?? ''}:${req.ip ?? ''}` }), validateBody(z.object({
  token: z.string().min(1),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
})), async (req, res, next) => {
  try {
    const result = await oauthService.introspectToken({
      token: req.body.token,
      clientId: req.body.client_id,
      clientSecret: req.body.client_secret,
      req,
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// ─── POST /oauth/revoke ──────────────────────────────────────────────────────

router.post('/revoke', enterpriseRateLimit({ route: 'oauth-revoke', windowMs: 15 * 60 * 1000, max: 50, identifierFrom: (req) => `${req.body?.client_id ?? ''}:${req.ip ?? ''}` }), validateBody(z.object({
  token: z.string().min(1),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
})), async (req, res, next) => {
  try {
    await oauthService.revokeToken({
      token: req.body.token,
      clientId: req.body.client_id,
      clientSecret: req.body.client_secret,
      req,
    });
    // RFC 7009: always 200
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

export default router;
