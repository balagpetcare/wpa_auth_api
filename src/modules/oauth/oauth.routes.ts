import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '../../middleware/validate.js';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import * as oauthService from './oauth.service.js';
import { AppError } from '../../lib/errors.js';
import { oauthAuthorizeRateLimit, oauthTokenRateLimit, oauthIntrospectRateLimit, oauthRevokeRateLimit } from '../../middleware/rateLimit.js';

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
});

router.get('/authorize', oauthAuthorizeRateLimit, authGuard, async (req: AuthenticatedRequest, res, next) => {
  try {
    const parsed = authorizeSchema.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ success: false, message: 'Invalid authorize request.', code: 'INVALID_REQUEST', errors: parsed.error.issues });
      return;
    }

    const q = parsed.data;
    const scopes = q.scope.split(' ').filter(Boolean);

    const result = await oauthService.createAuthorizationCode({
      clientId: q.client_id,
      redirectUri: q.redirect_uri,
      scopes,
      state: q.state,
      codeChallenge: q.code_challenge,
      codeChallengeMethod: q.code_challenge_method,
      userId: req.user!.id,
      req,
    });

    // In a real browser flow the server would redirect to redirect_uri?code=...&state=...
    // For API-first first-party apps, return JSON and let the client handle the redirect.
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

router.post('/token', oauthTokenRateLimit, async (req, res, next) => {
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

router.post('/introspect', oauthIntrospectRateLimit, validateBody(z.object({
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

router.post('/revoke', oauthRevokeRateLimit, validateBody(z.object({
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
