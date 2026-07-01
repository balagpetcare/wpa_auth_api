import { createHash } from 'crypto';
import jwt from 'jsonwebtoken';
import { prisma } from '../../lib/db.js';
import { config } from '../../config/index.js';
import {
  generateOpaqueToken,
  hashToken,
  signAccessToken,
  signRefreshToken,
  parseTtlToSeconds,
} from '../../lib/tokens.js';
import { AppError } from '../../lib/errors.js';
import { writeAuditLog, writeSecurityEvent } from '../../lib/audit.js';
import { Request } from 'express';

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

// ─── /oauth/authorize ────────────────────────────────────────────────────────

export async function createAuthorizationCode(opts: {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
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
  if (client.clientSecretHash) {
    if (!opts.clientSecret) throw new AppError('client_secret required.', 'INVALID_CLIENT', 401);
    const hash = createHash('sha256').update(opts.clientSecret).digest('hex');
    if (hash !== client.clientSecretHash) throw new AppError('Invalid client_secret.', 'INVALID_CLIENT', 401);
  }

  const codeHash = hashToken(opts.code);
  const record = await prisma.authorizationCode.findUnique({ where: { codeHash } });

  if (!record || record.usedAt || record.expiresAt < new Date()) {
    throw new AppError('Authorization code is invalid or expired.', 'INVALID_GRANT', 400);
  }
  if (record.clientId !== client.id) {
    throw new AppError('Code was not issued for this client.', 'INVALID_GRANT', 400);
  }
  if (record.redirectUri !== opts.redirectUri) {
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
  const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username, roles });
  const refreshToken = signRefreshToken(user.id);

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId: client.id,
      tokenHash: hashToken(refreshToken),
      scopes: record.scopes,
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      ipAddress: opts.req.ip ?? opts.req.socket.remoteAddress,
      userAgent: opts.req.headers['user-agent'],
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

  return buildTokenResponse(accessToken, refreshToken, record.scopes, user, roles);
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
  if (!stored || stored.revokedAt || stored.expiresAt < new Date()) {
    throw new AppError('Refresh token is invalid or revoked.', 'INVALID_GRANT', 400);
  }
  if (stored.clientId !== client.id) throw new AppError('Token was not issued for this client.', 'INVALID_GRANT', 400);

  const user = await prisma.user.findUnique({ where: { id: payload.sub } });
  if (!user || user.status !== 'ACTIVE') throw new AppError('User account is not active.', 'ACCOUNT_INACTIVE', 403);

  // Rotate
  const newRefresh = signRefreshToken(user.id);
  const scopes = opts.scopes?.length ? validateScopes(client, opts.scopes) : stored.scopes;

  await prisma.$transaction([
    prisma.refreshToken.update({ where: { tokenHash }, data: { revokedAt: new Date() } }),
    prisma.refreshToken.create({
      data: {
        userId: user.id,
        clientId: client.id,
        tokenHash: hashToken(newRefresh),
        scopes,
        expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
        ipAddress: opts.req.ip ?? opts.req.socket.remoteAddress,
        userAgent: opts.req.headers['user-agent'],
      },
    }),
  ]);

  const roles = await getUserRoleNames(user.id);
  const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username, roles });

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

export function getJwks() {
  if (config.JWT_RSA_PUBLIC_KEY) {
    // Parse RSA public key PEM and return JWK
    // Placeholder — production should use a proper JWK library (e.g. jose)
    // TODO: Replace with `jose` library for full JWK export when RSA keys are provided
    return {
      keys: [
        {
          kty: 'RSA',
          use: 'sig',
          alg: 'RS256',
          kid: 'wpa-rsa-1',
          // n, e would be extracted from the public key PEM via `jose`
          note: 'RSA key present — install `jose` and implement JWK export',
        },
      ],
    };
  }

  // Dev/symmetric fallback: return a minimal descriptor (not usable for verification externally)
  return {
    keys: [
      {
        kty: 'oct',
        use: 'sig',
        alg: 'HS256',
        kid: 'wpa-hs256-1',
        note: 'Symmetric key — set JWT_RSA_PRIVATE_KEY and JWT_RSA_PUBLIC_KEY for production RS256',
      },
    ],
  };
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

function verifyClientSecret(client: { clientSecretHash: string | null }, secret?: string) {
  if (!client.clientSecretHash) return; // public client
  if (!secret) throw new AppError('client_secret required.', 'INVALID_CLIENT', 401);
  const hash = createHash('sha256').update(secret).digest('hex');
  if (hash !== client.clientSecretHash) throw new AppError('Invalid client_secret.', 'INVALID_CLIENT', 401);
}

function buildTokenResponse(
  accessToken: string,
  refreshToken: string,
  scopes: string[],
  user: { id: string; email: string | null; username: string | null; displayName: string | null },
  roles: string[],
) {
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: 'Bearer',
    expires_in: parseTtlToSeconds(config.ACCESS_TOKEN_TTL),
    scope: scopes.join(' '),
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
