import { createHash } from 'crypto';
import jwt from 'jsonwebtoken';
import { prisma } from '../../lib/db.js';
import { config } from '../../config/index.js';
import {
  generateOpaqueToken,
  hashToken,
  signAccessToken,
  signRefreshToken,
  signIdToken,
  parseTtlToSeconds,
  timingSafeEqualHex,
} from '../../lib/tokens.js';
import { AppError } from '../../lib/errors.js';
import { writeAuditLog, writeSecurityEvent } from '../../lib/audit.js';
import { getRedisClient } from '../../lib/redis.js';
import { Request } from 'express';
import { logAbuseSignal } from '../../lib/antiAbuse.js';
import { exportJwks } from '../../lib/signingKeys.js';
import { getServiceAdminPermissions, adminAudiencesForPermissions } from '../../lib/adminAccess.js';
import type { IdTokenSigningAlg } from '../../lib/oidc.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function requireActiveClient(clientId: string, req?: Request) {
  const client = await prisma.authClient.findUnique({ where: { clientId } });
  if (!client || client.status !== 'ACTIVE') {
    throw new AppError('Unknown or disabled client.', 'INVALID_CLIENT', 401);
  }
  if (req && req.headers.origin) {
    const origin = req.headers.origin;
    // Allow if exact match or if wildcard '*' is explicitly allowed for this client
    if (!client.allowedOrigins.includes(origin) && !client.allowedOrigins.includes('*')) {
      console.warn(`[SECURITY] Blocked invalid origin "${origin}" for client "${client.id}"`);
      await writeSecurityEvent({
        type: 'SUSPICIOUS_OAUTH',
        severity: 'MEDIUM',
        metadata: { reason: 'invalid_origin', origin, clientId: client.id },
        req,
      });
      throw new AppError('Origin not allowed for this client.', 'INVALID_ORIGIN', 403);
    }
  }
  return client;
}

async function validateRedirectUri(client: { id: string, redirectUris: string[] }, redirectUri: string, req?: Request) {
  if (!client.redirectUris.includes(redirectUri)) {
    console.warn(`[SECURITY] Blocked invalid redirect_uri "${redirectUri}" for client "${client.id}"`);
    if (req) {
      await writeSecurityEvent({
        type: 'SUSPICIOUS_OAUTH',
        severity: 'HIGH',
        metadata: { reason: 'invalid_redirect_uri', redirectUri, clientId: client.id },
        req,
      });
      await logAbuseSignal({ route: 'oauth-authorize', req, clientId: client.id, identifier: `${client.id}:${redirectUri}`, threat: 'SUSPICIOUS_ACTIVITY_BLOCKED', blockAfter: 6 });
    }
    throw new AppError('redirect_uri is not registered for this client.', 'INVALID_REDIRECT_URI', 400);
  }
}

function validateScopes(client: { allowedScopes: string[] }, requested: string[]): string[] {
  const invalid = requested.filter((s) => !client.allowedScopes.includes(s));
  if (invalid.length) {
    throw new AppError(`Scopes not allowed for this client: ${invalid.join(', ')}`, 'INVALID_SCOPE', 400);
  }
  return requested;
}

async function getUserRoleNames(userId: string): Promise<string[]> {
  const rows = await prisma.userRole.findMany({ where: { userId }, include: { role: true } });
  return rows.map((r) => r.role.name);
}

// ─── /oauth/authorize — consent (third-party clients) ─────────────────────────
// Phase 2 module (docs/phase-2-core-identity-admin-modules.md): third-party
// clients previously received an authorization code immediately with no
// user consent step — a THIRD_PARTY_APP was silently auto-approved exactly
// like a trusted FIRST_PARTY_APP. FIRST_PARTY_APP (and SERVICE) behavior is
// preserved unchanged below (startAuthorization short-circuits straight to
// createAuthorizationCode for them, per "preserve existing trusted
// behavior"). THIRD_PARTY_APP clients now go through an explicit
// approve/deny consent step first.
//
// Pending consent requests are short-lived (5 minute) opaque tickets held in
// Redis rather than a Prisma model — nothing is granted until the user
// approves, and no schema migration was needed. Redis is already a hard
// production requirement (see lib/redis.ts), so this fails closed (503) if
// Redis is unavailable rather than silently skipping consent.

const CONSENT_TICKET_TTL_SECONDS = 5 * 60;

interface PendingConsent {
  clientId: string; // AuthClient.id (internal), not the public clientId
  redirectUri: string;
  scopes: string[];
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
  userId: string;
}

export async function validateAuthorizationRequest(opts: {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  codeChallenge?: string;
  codeChallengeMethod?: string;
  req?: Request;
}) {
  const client = await requireActiveClient(opts.clientId, opts.req);
  await validateRedirectUri(client, opts.redirectUri, opts.req);
  const scopes = validateScopes(client, opts.scopes.length ? opts.scopes : ['openid']);

  if (!client.clientSecretHash && client.type !== 'SERVICE') {
    if (!opts.codeChallenge) {
      throw new AppError('PKCE code_challenge is required for public clients.', 'INVALID_REQUEST', 400);
    }
    if ((opts.codeChallengeMethod ?? 'S256') !== 'S256') {
      throw new AppError('Public clients must use PKCE S256.', 'INVALID_REQUEST', 400);
    }
  }

  return { client, scopes };
}

export async function startAuthorization(opts: {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
  userId: string;
  req: Request;
}) {
  const { client, scopes } = await validateAuthorizationRequest(opts);

  if (client.type !== 'THIRD_PARTY_APP') {
    const result = await createAuthorizationCode({ ...opts, scopes });
    return { requiresConsent: false as const, ...result };
  }

  const redisClient = getRedisClient();
  if (!redisClient) {
    throw new AppError('Consent flow is temporarily unavailable.', 'SERVICE_UNAVAILABLE', 503);
  }

  const ticket = generateOpaqueToken(24);
  const pending: PendingConsent = {
    clientId: client.id,
    redirectUri: opts.redirectUri,
    scopes,
    state: opts.state,
    codeChallenge: opts.codeChallenge,
    codeChallengeMethod: opts.codeChallengeMethod,
    nonce: opts.nonce,
    userId: opts.userId,
  };
  await redisClient.set(`oauth-consent:${ticket}`, JSON.stringify(pending), 'EX', CONSENT_TICKET_TTL_SECONDS);

  return {
    requiresConsent: true as const,
    consentTicket: ticket,
    client: { name: client.name, slug: client.slug },
    scopes,
    redirectUri: opts.redirectUri,
    state: opts.state,
  };
}

export async function resolveConsent(opts: {
  consentTicket: string;
  decision: 'approve' | 'deny';
  userId: string;
  req: Request;
}) {
  const redisClient = getRedisClient();
  if (!redisClient) {
    throw new AppError('Consent flow is temporarily unavailable.', 'SERVICE_UNAVAILABLE', 503);
  }

  const key = `oauth-consent:${opts.consentTicket}`;
  const raw = await redisClient.get(key);
  if (!raw) {
    throw new AppError('This consent request has expired or was already used. Please restart sign-in.', 'INVALID_CONSENT_TICKET', 400);
  }
  await redisClient.del(key); // one-time use regardless of outcome

  const pending = JSON.parse(raw) as PendingConsent;
  if (pending.userId !== opts.userId) {
    // Defense in depth: a consent ticket may only be resolved by the same
    // user whose session created it via /authorize.
    await writeSecurityEvent({
      type: 'SUSPICIOUS_OAUTH',
      severity: 'HIGH',
      userId: opts.userId,
      metadata: { reason: 'consent_ticket_user_mismatch', clientId: pending.clientId },
      req: opts.req,
    });
    throw new AppError('This consent request does not belong to your session.', 'INVALID_CONSENT_TICKET', 403);
  }

  const client = await prisma.authClient.findUnique({ where: { id: pending.clientId } });
  if (!client || client.status !== 'ACTIVE') {
    throw new AppError('Unknown or disabled client.', 'INVALID_CLIENT', 401);
  }

  if (opts.decision === 'deny') {
    await writeAuditLog({
      userId: opts.userId,
      clientId: client.id,
      action: 'OAUTH_AUTHORIZE',
      resource: 'authorization_code',
      metadata: { decision: 'denied', scopes: pending.scopes, redirectUri: pending.redirectUri },
      req: opts.req,
    });
    return {
      approved: false as const,
      redirectUri: pending.redirectUri,
      state: pending.state,
      error: 'access_denied' as const,
    };
  }

  const result = await createAuthorizationCode({
    clientId: client.clientId,
    redirectUri: pending.redirectUri,
    scopes: pending.scopes,
    state: pending.state,
    codeChallenge: pending.codeChallenge,
    codeChallengeMethod: pending.codeChallengeMethod,
    nonce: pending.nonce,
    userId: opts.userId,
    req: opts.req,
  });

  return {
    approved: true as const,
    redirectUri: pending.redirectUri,
    ...result,
  };
}

// ─── /oauth/authorize ────────────────────────────────────────────────────────

export async function createAuthorizationCode(opts: {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
  userId: string;
  req: Request;
}) {
  const client = await requireActiveClient(opts.clientId, opts.req);
  await validateRedirectUri(client, opts.redirectUri, opts.req);
  const scopes = validateScopes(client, opts.scopes.length ? opts.scopes : ['openid']);

  const rawCode = generateOpaqueToken(32);
  const codeHash = hashToken(rawCode);

  await prisma.authorizationCode.create({
    data: {
      codeHash,
      userId: opts.userId,
      clientId: client.id,
      redirectUri: opts.redirectUri,
      scopes,
      state: opts.state,
      codeChallenge: opts.codeChallenge,
      codeChallengeMethod: opts.codeChallengeMethod,
      nonce: opts.nonce,
      // Phase 2.5: this authorization code can only be reached via an
      // interactive session (authGuard-protected /oauth/authorize, or the
      // consent-approve step which itself requires the same authenticated
      // session) — so "now" is a reasonable OIDC auth_time for this grant.
      authTime: new Date(),
      expiresAt: new Date(Date.now() + config.AUTH_CODE_TTL_SECONDS * 1000),
    },
  });

  await writeAuditLog({
    userId: opts.userId,
    clientId: client.id,
    action: 'OAUTH_AUTHORIZE',
    resource: 'authorization_code',
    metadata: { scopes, redirectUri: opts.redirectUri },
    req: opts.req,
  });

  return { code: rawCode, state: opts.state };
}

// ─── /oauth/token — authorization_code ───────────────────────────────────────

export async function exchangeAuthorizationCode(opts: {
  code: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  codeVerifier?: string;
  req: Request;
}) {
  const client = await requireActiveClient(opts.clientId, opts.req);

  // Verify client secret for confidential clients
  if (client.type === 'SERVICE') {
    if (!client.clientSecretHash) {
      throw new AppError('Client configuration error: SERVICE client must have a client secret configured.', 'INVALID_CLIENT', 401);
    }
  }

  if (client.clientSecretHash) {
    if (!opts.clientSecret) {
      throw new AppError('client_secret required.', 'INVALID_CLIENT', 401);
    }
    const hash = createHash('sha256').update(opts.clientSecret).digest('hex');
    if (!timingSafeEqualHex(hash, client.clientSecretHash)) {
      await logAbuseSignal({ route: 'oauth-token', req: opts.req, clientId: client.id, identifier: `${client.id}:${opts.clientId}`, threat: 'OAUTH_CLIENT_SECRET_ABUSE', blockAfter: 5, blockTtlMs: 60 * 60 * 1000 });
      throw new AppError('Invalid client_secret.', 'INVALID_CLIENT', 401);
    }
  } else {
    const isPublicAllowed = client.type === 'FIRST_PARTY_APP' || client.type === 'THIRD_PARTY_APP';
    if (!isPublicAllowed) {
      throw new AppError('Client requires a client secret.', 'INVALID_CLIENT', 401);
    }
  }

  const codeHash = hashToken(opts.code);
  const record = await prisma.authorizationCode.findUnique({ where: { codeHash } });

  if (!record || record.usedAt || record.expiresAt < new Date()) {
    await logAbuseSignal({ route: 'oauth-token', req: opts.req, clientId: client.id, identifier: `${client.id}:${opts.code.slice(0, 16)}`, threat: 'SUSPICIOUS_ACTIVITY_BLOCKED', blockAfter: 6 });
    throw new AppError('Authorization code is invalid or expired.', 'INVALID_GRANT', 400);
  }
  if (record.clientId !== client.id) {
    throw new AppError('Code was not issued for this client.', 'INVALID_GRANT', 400);
  }
  if (record.redirectUri !== opts.redirectUri) {
    await logAbuseSignal({ route: 'oauth-token', req: opts.req, clientId: client.id, identifier: `${client.id}:${opts.redirectUri}`, threat: 'SUSPICIOUS_ACTIVITY_BLOCKED', blockAfter: 6 });
    throw new AppError('redirect_uri mismatch.', 'INVALID_GRANT', 400);
  }

  // PKCE verification
  if (record.codeChallenge) {
    if (!opts.codeVerifier) throw new AppError('code_verifier required.', 'INVALID_GRANT', 400);
    const method = record.codeChallengeMethod ?? 'S256';
    let derived: string;
    if (method === 'S256') {
      derived = createHash('sha256').update(opts.codeVerifier).digest('base64url');
    } else {
      derived = opts.codeVerifier; // plain
    }
    if (derived !== record.codeChallenge) throw new AppError('PKCE verification failed.', 'INVALID_GRANT', 400);
  }

  // Mark code used
  await prisma.authorizationCode.update({ where: { codeHash }, data: { usedAt: new Date() } });

  const user = await prisma.user.findUnique({ where: { id: record.userId } });
  if (!user || user.status !== 'ACTIVE') throw new AppError('User account is not active.', 'ACCOUNT_INACTIVE', 403);

  const roles = await getUserRoleNames(user.id);
  // Pre-existing gap fixed here (Global Super Admin Stage 2): this call
  // previously ignored client.audience entirely and always signed with the
  // global default. Clients without a configured audience are unaffected
  // (same fallback as before); clients that DO set one (e.g. Furtail,
  // and now the admin-frontend OAuth clients) now correctly receive it.
  const servicePerms = await getServiceAdminPermissions(user.id);
  const adminAudiences = adminAudiencesForPermissions(servicePerms);
  const baseAudience = client.audience ?? config.ACCESS_TOKEN_AUDIENCE;
  const accessAudience = adminAudiences.length > 0 ? Array.from(new Set([baseAudience, ...adminAudiences])) : baseAudience;
  const accessToken = signAccessToken(
    { sub: user.id, email: user.email, username: user.username, roles, ...(servicePerms.length > 0 ? { perms: servicePerms } : {}) },
    accessAudience,
  );
  const refreshToken = signRefreshToken(user.id, client.audience ?? undefined);

  const familyId = generateOpaqueToken(16);

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId: client.id,
      tokenHash: hashToken(refreshToken),
      scopes: record.scopes,
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      ipAddress: opts.req.ip ?? opts.req.socket.remoteAddress,
      userAgent: opts.req.headers['user-agent'],
      familyId,
    },
  });

  await writeAuditLog({
    userId: user.id,
    clientId: client.id,
    action: 'OAUTH_TOKEN_ISSUED',
    resource: 'token',
    metadata: { grant_type: 'authorization_code', scopes: record.scopes },
    req: opts.req,
  });

  const idToken = record.scopes.includes('openid')
    ? await buildIdToken({ user, client, scopes: record.scopes, nonce: record.nonce, authTime: record.authTime })
    : undefined;

  return buildTokenResponse(accessToken, refreshToken, record.scopes, user, roles, idToken);
}

// ─── /oauth/token — refresh_token ────────────────────────────────────────────

export async function exchangeRefreshToken(opts: {
  refreshToken: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  req: Request;
}) {
  const client = await requireActiveClient(opts.clientId, opts.req);
  verifyClientSecret(client, opts.clientSecret);

  let payload: { sub: string };
  try {
    payload = jwt.verify(opts.refreshToken, config.JWT_REFRESH_SECRET) as { sub: string };
  } catch {
    throw new AppError('Invalid or expired refresh token.', 'INVALID_GRANT', 400);
  }

  const tokenHash = hashToken(opts.refreshToken);
  const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });
  if (!stored) {
    throw new AppError('Refresh token is invalid or revoked.', 'INVALID_GRANT', 400);
  }

  // Reuse detection:
  if (stored.revokedAt || stored.expiresAt < new Date()) {
    if (stored.revokedAt && stored.revocationReason === 'ROTATED') {
      // Reused a rotated token!
      if (!stored.reusedAt) {
        // Mark as reused to prevent duplicate processing
        await prisma.refreshToken.update({
          where: { id: stored.id },
          data: { reusedAt: new Date() },
        });

        // Revoke the session family
        if (stored.familyId) {
          await prisma.refreshToken.updateMany({
            where: { familyId: stored.familyId, userId: stored.userId, revokedAt: null },
            data: {
              revokedAt: new Date(),
              revocationReason: 'REUSE_DETECTED',
            },
          });
        }

        // Increase abuse risk score for IP
        await logAbuseSignal({
          route: 'oauth-token',
          req: opts.req,
          clientId: client.id,
          identifier: `${client.id}:${opts.clientId}`,
          threat: 'OAUTH_CLIENT_SECRET_ABUSE',
          blockAfter: 3,
        });

        // Write SecurityEvent
        await writeSecurityEvent({
          type: 'TOKEN_REUSE_DETECTED',
          severity: 'HIGH',
          metadata: {
            userId: stored.userId,
            clientId: stored.clientId,
            familyId: stored.familyId,
            ipAddress: opts.req.ip ?? opts.req.socket.remoteAddress,
            userAgent: opts.req.headers['user-agent'],
          },
          req: opts.req,
        });
      }

      throw new AppError('Refresh token reuse detected.', 'INVALID_GRANT', 400);
    }

    // Normal invalid/revoked/expired token
    await logAbuseSignal({ route: 'oauth-token', req: opts.req, clientId: client.id, identifier: `${client.id}:${opts.refreshToken.slice(0, 16)}`, threat: 'SUSPICIOUS_ACTIVITY_BLOCKED', blockAfter: 6 });
    throw new AppError('Refresh token is invalid or revoked.', 'INVALID_GRANT', 400);
  }

  if (stored.clientId !== client.id) throw new AppError('Token was not issued for this client.', 'INVALID_GRANT', 400);

  const user = await prisma.user.findUnique({ where: { id: payload.sub } });
  if (!user || user.status !== 'ACTIVE') throw new AppError('User account is not active.', 'ACCOUNT_INACTIVE', 403);

  // Rotate
  const newRefresh = signRefreshToken(user.id);
  const newHash = hashToken(newRefresh);
  const scopes = opts.scopes?.length ? validateScopes(client, opts.scopes) : stored.scopes;
  const familyId = stored.familyId || generateOpaqueToken(16);

  // Use a transaction to create the new token and update the old one
  const [newClientToken] = await prisma.$transaction([
    prisma.refreshToken.create({
      data: {
        userId: user.id,
        clientId: client.id,
        tokenHash: newHash,
        scopes,
        expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
        ipAddress: opts.req.ip ?? opts.req.socket.remoteAddress,
        userAgent: opts.req.headers['user-agent'],
        familyId,
      },
    }),
    prisma.refreshToken.update({
      where: { id: stored.id },
      data: {
        revokedAt: new Date(),
        revocationReason: 'ROTATED',
      },
    }),
  ]);

  // Link the old token to the newly created token
  await prisma.refreshToken.update({
    where: { id: stored.id },
    data: {
      replacedByTokenId: newClientToken.id,
    },
  });

  const roles = await getUserRoleNames(user.id);
  const servicePerms = await getServiceAdminPermissions(user.id);
  const adminAudiences = adminAudiencesForPermissions(servicePerms);
  const baseAudience = client.audience ?? config.ACCESS_TOKEN_AUDIENCE;
  const accessAudience = adminAudiences.length > 0 ? Array.from(new Set([baseAudience, ...adminAudiences])) : baseAudience;
  const accessToken = signAccessToken(
    { sub: user.id, email: user.email, username: user.username, roles, ...(servicePerms.length > 0 ? { perms: servicePerms } : {}) },
    accessAudience,
  );

  await writeAuditLog({
    userId: user.id,
    clientId: client.id,
    action: 'OAUTH_TOKEN_ISSUED',
    metadata: { grant_type: 'refresh_token', scopes },
    req: opts.req,
  });

  return buildTokenResponse(accessToken, newRefresh, scopes, user, roles);
}

// ─── /oauth/token — client_credentials ───────────────────────────────────────

export async function clientCredentials(opts: {
  clientId: string;
  clientSecret: string;
  scopes: string[];
  req: Request;
}) {
  const client = await requireActiveClient(opts.clientId, opts.req);
  if (client.type !== 'SERVICE') {
    throw new AppError('client_credentials grant is only available to SERVICE clients.', 'UNAUTHORIZED_CLIENT', 403);
  }
  verifyClientSecret(client, opts.clientSecret);

  const scopes = validateScopes(client, opts.scopes.length ? opts.scopes : client.allowedScopes);

  const rawToken = generateOpaqueToken(48);
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + config.SERVICE_TOKEN_TTL_SECONDS * 1000);

  await prisma.serviceAccessToken.create({
    data: { clientId: client.id, tokenHash, scopes, expiresAt },
  });

  await writeAuditLog({
    clientId: client.id,
    action: 'OAUTH_TOKEN_ISSUED',
    metadata: { grant_type: 'client_credentials', scopes },
    req: opts.req,
  });

  return {
    access_token: rawToken,
    token_type: 'Bearer',
    expires_in: config.SERVICE_TOKEN_TTL_SECONDS,
    scope: scopes.join(' '),
  };
}

// ─── /oauth/userinfo ─────────────────────────────────────────────────────────

export async function getUserInfo(userId: string) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new AppError('User not found.', 'NOT_FOUND', 404);
  const roles = await getUserRoleNames(userId);

  return {
    sub: user.id,
    email: user.email,
    email_verified: !!user.emailVerifiedAt,
    phone_number: user.phone,
    phone_number_verified: !!user.phoneVerifiedAt,
    preferred_username: user.username,
    name: user.displayName,
    picture: user.avatarUrl,
    roles,
    updated_at: Math.floor(user.updatedAt.getTime() / 1000),
  };
}

// ─── /oauth/jwks ─────────────────────────────────────────────────────────────
//
// Phase 2 fix (docs/phase-2-core-identity-admin-modules.md): when
// JWT_RSA_PUBLIC_KEY is configured, this now returns a real RFC 7517 JWK
// with correctly derived `n`/`e` — Node's built-in `crypto.createPublicKey(
// ...).export({ format: 'jwk' })` (available since Node 15) does the PEM ->
// JWK conversion, so no new dependency (e.g. `jose`) was needed.
//
// ⚠️ Access/refresh tokens are still always signed with HS256 (see
// src/lib/tokens.ts signAccessToken/signRefreshToken) — switching token
// *signing* to RS256 using JWT_RSA_PRIVATE_KEY is a separate, larger change
// (it touches every place that verifies an access token, both internally
// and for any relying party) and is intentionally out of scope here. This
// endpoint is therefore standards-compliant and ready for that future
// RS256 cutover, but until tokens are actually signed with the matching
// RSA private key, a relying party fetching this JWKS still cannot verify
// WPA-issued access tokens with it — only the HS256 dev fallback below
// applies today, and HS256 is symmetric (not usable for third-party
// signature verification by design; the secret must stay server-side).
// TODO (tracked, not implemented here): switch signAccessToken/
// signRefreshToken to RS256 with JWT_RSA_PRIVATE_KEY once a key rotation
// story (see rotation note below) is in place.
//
// JWKS now comes from the signing-key registry helper so active public keys
// can overlap during rotation windows without exposing retired material.
// The helper falls back to the configured RSA env key and then the legacy
// HS256 descriptor when no public signing key material is available.
export async function getJwks() {
  return exportJwks();
}

// ─── /oauth/introspect ───────────────────────────────────────────────────────

export async function introspectToken(opts: {
  token: string;
  clientId: string;
  clientSecret?: string;
  req: Request;
}) {
  const client = await requireActiveClient(opts.clientId, opts.req);
  verifyClientSecret(client, opts.clientSecret);

  const inactive = { active: false };

  // Try service access token first
  const tokenHash = hashToken(opts.token);
  const serviceToken = await prisma.serviceAccessToken.findUnique({ where: { tokenHash } });
  if (serviceToken) {
    if (serviceToken.revokedAt || serviceToken.expiresAt < new Date()) return inactive;
    await writeAuditLog({ clientId: client.id, action: 'OAUTH_INTROSPECT', metadata: { token_type: 'service' }, req: opts.req });
    return {
      active: true,
      token_type: 'Bearer',
      scope: serviceToken.scopes.join(' '),
      client_id: opts.clientId,
      exp: Math.floor(serviceToken.expiresAt.getTime() / 1000),
      iat: Math.floor(serviceToken.createdAt.getTime() / 1000),
    };
  }

  // Try JWT access token
  try {
    const payload = jwt.verify(opts.token, config.JWT_ACCESS_SECRET) as any;
    await writeAuditLog({ clientId: client.id, action: 'OAUTH_INTROSPECT', metadata: { token_type: 'jwt', sub: payload.sub }, req: opts.req });
    return {
      active: true,
      token_type: 'Bearer',
      sub: payload.sub,
      email: payload.email,
      username: payload.username,
      roles: payload.roles,
      scope: (payload.roles ?? []).join(' '),
      exp: payload.exp,
      iat: payload.iat,
      iss: config.OAUTH_ISSUER,
    };
  } catch {
    return inactive;
  }
}

// ─── /oauth/revoke ───────────────────────────────────────────────────────────

export async function revokeToken(opts: {
  token: string;
  clientId: string;
  clientSecret?: string;
  req: Request;
}) {
  const client = await requireActiveClient(opts.clientId, opts.req);
  verifyClientSecret(client, opts.clientSecret);

  const tokenHash = hashToken(opts.token);

  // Revoke service token if found
  const serviceToken = await prisma.serviceAccessToken.findUnique({ where: { tokenHash } });
  if (serviceToken) {
    await prisma.serviceAccessToken.update({ where: { tokenHash }, data: { revokedAt: new Date() } });
    await writeAuditLog({ clientId: client.id, action: 'OAUTH_TOKEN_REVOKED', metadata: { token_type: 'service' }, req: opts.req });
    return;
  }

  // Revoke refresh token if found
  const refreshToken = await prisma.refreshToken.findUnique({ where: { tokenHash } });
  if (refreshToken && refreshToken.clientId === client.id) {
    await prisma.refreshToken.update({ where: { tokenHash }, data: { revokedAt: new Date() } });
    await writeAuditLog({ userId: refreshToken.userId, clientId: client.id, action: 'OAUTH_TOKEN_REVOKED', metadata: { token_type: 'refresh' }, req: opts.req });
  }
  // Per RFC 7009: always return 200 even if token not found
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

function verifyClientSecret(client: { type: string; clientSecretHash: string | null }, secret?: string) {
  // SERVICE/confidential clients must always have a client secret configured and require validation
  if (client.type === 'SERVICE') {
    if (!client.clientSecretHash) {
      throw new AppError('Client configuration error: SERVICE client must have a client secret configured.', 'INVALID_CLIENT', 401);
    }
  }

  if (client.clientSecretHash) {
    if (!secret) throw new AppError('client_secret required.', 'INVALID_CLIENT', 401);
    const hash = createHash('sha256').update(secret).digest('hex');
    if (!timingSafeEqualHex(hash, client.clientSecretHash)) throw new AppError('Invalid client_secret.', 'INVALID_CLIENT', 401);
  } else {
    // If clientSecretHash is null/empty, check if this is an explicitly allowed public client
    const isPublicAllowed = client.type === 'FIRST_PARTY_APP' || client.type === 'THIRD_PARTY_APP';
    if (!isPublicAllowed) {
      throw new AppError('Client requires a client secret.', 'INVALID_CLIENT', 401);
    }
  }
}

function buildTokenResponse(
  accessToken: string,
  refreshToken: string,
  scopes: string[],
  user: { id: string; email: string | null; username: string | null; displayName: string | null },
  roles: string[],
  idToken?: string,
) {
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: 'Bearer',
    expires_in: parseTtlToSeconds(config.ACCESS_TOKEN_TTL),
    scope: scopes.join(' '),
    // Phase 2.5 (docs/phase-2-5-public-auth-rs256-oidc.md): only present
    // when the authorization request included the `openid` scope, per the
    // OIDC spec. RS256-signed (see signIdToken in lib/tokens.ts) when RSA
    // keys are configured; access_token above remains the pre-existing
    // internal HS256 JWT (signAccessToken) and is unaffected by this change.
    ...(idToken ? { id_token: idToken } : {}),
    // Convenience fields (non-standard, for first-party apps)
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      displayName: user.displayName,
      roles,
    },
  };
}

// Phase 2.5 (docs/phase-2-5-public-auth-rs256-oidc.md): builds the OIDC
// id_token per OpenID Connect Core 1.0 §2 (ID Token). Only issued when the
// authorization request's scope included `openid` (checked by the caller).
async function buildIdToken(opts: {
  user: { id: string; email: string | null; username: string | null; displayName: string | null; emailVerifiedAt: Date | null };
  client: { clientId: string; oidcIdTokenSigningAlg: IdTokenSigningAlg | null };
  scopes: string[];
  nonce: string | null;
  authTime: Date | null;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    iss: config.OAUTH_ISSUER,
    sub: opts.user.id,
    aud: opts.client.clientId,
    iat: now,
    // `exp` is also set by signIdToken's `expiresIn`, but jsonwebtoken
    // computes that internally from `iat`-at-sign-time — setting it here
    // explicitly would conflict with the `expiresIn` option, so it is left
    // to signIdToken. Included in the type comment for clarity: exp = iat +
    // ACCESS_TOKEN_TTL (matches the access_token lifetime).
  };
  if (opts.authTime) claims.auth_time = Math.floor(opts.authTime.getTime() / 1000);
  if (opts.nonce) claims.nonce = opts.nonce;

  if (opts.scopes.includes('profile')) {
    claims.name = opts.user.displayName ?? opts.user.username ?? undefined;
    claims.preferred_username = opts.user.username ?? undefined;
  }
  if (opts.scopes.includes('email') && opts.user.email) {
    claims.email = opts.user.email;
    claims.email_verified = !!opts.user.emailVerifiedAt;
  }

  return signIdToken(claims, parseTtlToSeconds(config.ACCESS_TOKEN_TTL), opts.client.oidcIdTokenSigningAlg ?? 'HS256');
}
