// System-browser OIDC login for enterprise organizations, brokered entirely
// server-side: the mobile app opens /auth/enterprise/:orgSlug/start in the
// system browser; this API redirects to the org's IdP with authorization
// code + PKCE (the API's own verifier toward the IdP), receives the IdP
// callback, exchanges the code (client secret never leaves this server),
// verifies the id_token (signature via the org's JWKS, iss, aud, exp,
// nonce), resolves/creates the Central Auth identity, and finally hands the
// APP a single-use PKCE-bound authorization code — the same mobile
// completion contract as social login (mobileAuthCode.service.ts).
//
// SAML is NOT implemented: a SAML-protocol org gets a typed
// ENTERPRISE_PROVIDER_UNSUPPORTED error, never a fake flow.
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import type { Request } from 'express';
import { prisma } from '../../lib/db.js';
import { config } from '../../config/index.js';
import { AppError, ErrorCodes } from '../../lib/errors.js';
import { decryptCredentialPayload } from '../../lib/credentialEncryption.js';
import { verifyIdToken } from './identity-providers/jwksVerifier.js';
import { OAuthProvider } from '@prisma/client';
import type { NormalizedIdentityProfile } from './identity-providers/types.js';
import { resolveClient } from './auth.service.js';

type DiscoveryDoc = {
  authorization_endpoint?: string;
  token_endpoint?: string;
  jwks_uri?: string;
};

const discoveryCache = new Map<string, { doc: DiscoveryDoc; fetchedAt: number }>();
const DISCOVERY_TTL_MS = 10 * 60 * 1000;

async function discover(issuer: string): Promise<DiscoveryDoc> {
  const cached = discoveryCache.get(issuer);
  if (cached && Date.now() - cached.fetchedAt < DISCOVERY_TTL_MS) return cached.doc;
  const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new AppError('Enterprise IdP discovery failed.', 'PROVIDER_MISCONFIGURED', 502);
  }
  const doc = (await res.json()) as DiscoveryDoc;
  discoveryCache.set(issuer, { doc, fetchedAt: Date.now() });
  return doc;
}

async function getOidcRow(orgSlug: string) {
  const row = await prisma.enterpriseIdentityProvider.findUnique({ where: { orgSlug } });
  if (!row || !row.enabled) {
    throw new AppError('This organization is not configured for enterprise login.', ErrorCodes.PROVIDER_DISABLED, 503);
  }
  if (row.protocol !== 'OIDC') {
    throw new AppError(
      'This organization uses an identity protocol that is not supported yet.',
      'ENTERPRISE_PROVIDER_UNSUPPORTED',
      501,
      { protocol: row.protocol },
    );
  }
  if (!row.issuer || !row.clientId || !row.clientSecretEncrypted || !row.redirectUri) {
    throw new AppError('Enterprise OIDC provider is misconfigured.', 'PROVIDER_MISCONFIGURED', 400);
  }
  return row;
}

async function resolveEndpoints(row: { issuer: string | null; authorizationUrl: string | null; tokenUrl: string | null; jwksUri: string | null }) {
  let { authorizationUrl, tokenUrl, jwksUri } = row;
  if (!authorizationUrl || !tokenUrl || !jwksUri) {
    const doc = await discover(row.issuer as string);
    authorizationUrl = authorizationUrl || doc.authorization_endpoint || null;
    tokenUrl = tokenUrl || doc.token_endpoint || null;
    jwksUri = jwksUri || doc.jwks_uri || null;
  }
  if (!authorizationUrl || !tokenUrl || !jwksUri) {
    throw new AppError('Enterprise OIDC provider is misconfigured.', 'PROVIDER_MISCONFIGURED', 400);
  }
  return { authorizationUrl, tokenUrl, jwksUri };
}

export async function getEnterpriseStartRedirect(orgSlug: string, req: Request): Promise<string> {
  const row = await getOidcRow(orgSlug);
  const { authorizationUrl } = await resolveEndpoints(row);

  const nonce = crypto.randomBytes(16).toString('base64url');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  const redirectContext = {
    redirect_uri: typeof req.query.redirect_uri === 'string' ? req.query.redirect_uri : undefined,
    state: typeof req.query.state === 'string' ? req.query.state : undefined,
    code_challenge: typeof req.query.code_challenge === 'string' ? req.query.code_challenge : undefined,
  };
  const appClientIdParam = typeof req.query.app_client_id === 'string' ? req.query.app_client_id : undefined;
  const requestingClient = appClientIdParam ? await resolveClient(appClientIdParam, req) : null;

  const state = jwt.sign(
    {
      enterpriseOrg: orgSlug,
      nonce,
      codeVerifier,
      redirectContext,
      clientDbId: requestingClient?.id ?? null,
      appClientId: appClientIdParam ?? null,
    },
    config.JWT_ACCESS_SECRET,
    { expiresIn: '10m' },
  );

  const u = new URL(authorizationUrl);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', row.clientId as string);
  u.searchParams.set('redirect_uri', row.redirectUri as string);
  u.searchParams.set('scope', 'openid email profile');
  u.searchParams.set('state', state);
  u.searchParams.set('nonce', nonce);
  u.searchParams.set('code_challenge', codeChallenge);
  u.searchParams.set('code_challenge_method', 'S256');
  return u.toString();
}

export type EnterpriseCallbackVerified = {
  profile: NormalizedIdentityProfile;
  appClientId: string | undefined;
  state: string;
};

export async function verifyEnterpriseCallback(code: string, state: string): Promise<EnterpriseCallbackVerified> {
  let payload: {
    enterpriseOrg?: string;
    nonce?: string;
    codeVerifier?: string;
    appClientId?: string | null;
  };
  try {
    payload = jwt.verify(state, config.JWT_ACCESS_SECRET) as typeof payload;
  } catch {
    throw new AppError('Invalid or expired state.', 'INVALID_STATE', 400);
  }
  if (!payload.enterpriseOrg) throw new AppError('Invalid or expired state.', 'INVALID_STATE', 400);

  const row = await getOidcRow(payload.enterpriseOrg);
  const { tokenUrl, jwksUri } = await resolveEndpoints(row);
  const secret = (decryptCredentialPayload(JSON.parse(row.clientSecretEncrypted as string)) as { clientSecret?: string }).clientSecret;
  if (!secret) throw new AppError('Enterprise OIDC provider is misconfigured.', 'PROVIDER_MISCONFIGURED', 400);

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: row.redirectUri as string,
    client_id: row.clientId as string,
    client_secret: secret,
    ...(payload.codeVerifier ? { code_verifier: payload.codeVerifier } : {}),
  });
  const tokenRes = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!tokenRes.ok) {
    throw new AppError('Enterprise token exchange failed.', ErrorCodes.INVALID_PROVIDER_TOKEN, 502);
  }
  const tokenJson = (await tokenRes.json()) as { id_token?: string };
  if (!tokenJson.id_token) {
    throw new AppError('Enterprise IdP did not return an id_token.', ErrorCodes.INVALID_PROVIDER_TOKEN, 502);
  }

  const idPayload = await verifyIdToken(tokenJson.id_token, {
    jwksUri,
    issuer: row.issuer as string,
    audience: row.clientId as string,
    nonce: payload.nonce,
  });
  const sub = typeof idPayload.sub === 'string' ? idPayload.sub : '';
  if (!sub) throw new AppError('Enterprise token missing subject.', ErrorCodes.INVALID_PROVIDER_TOKEN, 401);

  return {
    profile: {
      provider: OAuthProvider.ENTERPRISE,
      // Namespace the subject by org so two orgs' subjects can never collide.
      providerUserId: `${payload.enterpriseOrg}:${sub}`,
      email: typeof idPayload.email === 'string' ? idPayload.email : undefined,
      emailVerified: idPayload.email_verified === true,
      displayName: typeof idPayload.name === 'string' ? idPayload.name : undefined,
      avatarUrl: typeof idPayload.picture === 'string' ? idPayload.picture : undefined,
      rawClaims: idPayload as Record<string, unknown>,
    },
    appClientId: payload.appClientId ?? undefined,
    state,
  };
}
