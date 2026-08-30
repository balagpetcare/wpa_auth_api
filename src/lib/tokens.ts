import jwt from 'jsonwebtoken';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import { config } from '../config/index.js';
import { getCurrentSigningKeyMaterial } from './signingKeys.js';
import type { IdTokenSigningAlg } from './oidc.js';

export interface AccessTokenPayload {
  sub: string;
  email: string | null;
  username: string | null;
  // Best-effort display name, included so relying-party APIs (e.g. the
  // Furtail API's JIT user-provisioning — see getOrProvisionUser /
  // buildProvisionedProfileSeed) can seed a real name for a brand-new
  // local profile instead of falling back to a generic placeholder. Never
  // required/verified — purely a convenience claim, the source of truth
  // for a user's identity remains this service's own User row.
  name?: string | null;
  roles: string[];
  sid?: string;
  aud?: string | string[];
  // Small, bounded set of service-scoped wildcard permissions (e.g.
  // "bpa:*") for Global Super Admin-style principals only. Deliberately
  // NOT a general permission dump — see docs on the bpa-admin session
  // cookie 4KB/Nginx-502 incident this is designed to avoid repeating.
  perms?: string[];
}

// Additive multi-client audience support (Furtail centralized-auth
// onboarding). Tokens are still SIGNED with a single audience — either the
// requesting AuthClient's own `audience` column (e.g. "furtail-mobile") or,
// when the client has none configured, the global default
// config.ACCESS_TOKEN_AUDIENCE (e.g. "bpa-mobile", unchanged for BPA).
// Verification accepts any audience in getAllowedAudiences() so a second
// first-party app can be onboarded without invalidating existing tokens.
export function getAllowedAudiences(): string[] {
  const extra = config.ADDITIONAL_JWT_AUDIENCES.split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return Array.from(new Set([config.ACCESS_TOKEN_AUDIENCE, ...extra]));
}

export function signAccessToken(payload: AccessTokenPayload, audience?: string | string[]): string {
  const { aud: _ignored, ...claims } = payload;
  return jwt.sign(claims, config.JWT_ACCESS_SECRET, {
    expiresIn: config.ACCESS_TOKEN_TTL as any,
    issuer: config.OAUTH_ISSUER,
    audience: audience ?? config.ACCESS_TOKEN_AUDIENCE,
  });
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  return jwt.verify(token, config.JWT_ACCESS_SECRET, {
    issuer: config.OAUTH_ISSUER,
    audience: getAllowedAudiences() as any,
  }) as unknown as AccessTokenPayload;
}

export function signRefreshToken(userId: string, audience?: string): string {
  const jti = randomBytes(16).toString('hex');
  return jwt.sign({ sub: userId, jti }, config.JWT_REFRESH_SECRET, {
    expiresIn: config.REFRESH_TOKEN_TTL as any,
    issuer: config.OAUTH_ISSUER,
    audience: audience ?? config.ACCESS_TOKEN_AUDIENCE,
  });
}

export function verifyRefreshToken(token: string): { sub: string } {
  return jwt.verify(token, config.JWT_REFRESH_SECRET, {
    issuer: config.OAUTH_ISSUER,
    audience: getAllowedAudiences() as any,
  }) as { sub: string };
}

// ─── OIDC id_token (RS256) ─────────────────────────────────────────────────
// Phase 2.5 (docs/phase-2-5-public-auth-rs256-oidc.md): the internal
// access/refresh tokens above (signAccessToken/signRefreshToken) remain
// HS256 — they are consumed only by this API itself (authGuard,
// verifyAccessToken, the admin panel, resource-server style checks) and
// switching their signing algorithm project-wide is a much larger, riskier
// change than this pass is scoped for (every internal verify call site,
// the admin session flow, refresh rotation, etc. would all need touching).
// That is unchanged and still HS256 — documented explicitly here and in the
// Phase 2.5 report rather than silently left ambiguous.
//
// The actual OIDC-standard artifact a third-party relying party needs to
// verify against JWKS is the `id_token` returned from the authorization_code
// grant when `openid` is in scope. That is signed with RS256 (using
// JWT_RSA_PRIVATE_KEY) whenever an RSA key pair is configured, with `kid`
// matching the JWKS response (getJwks() in oauth.service.ts, both driven by
// the same config.JWT_KEY_ID) — so a client can select the right key by kid.
//
// If no RSA key pair is configured, id_token issuance falls back to HS256
// signed with JWT_ACCESS_SECRET, clearly marked as a **local-development-only
// path**: JWKS has no usable key material for HS256 (symmetric secrets are
// never published), so a real relying party cannot verify an HS256 id_token
// against this server's JWKS in that fallback mode. This mirrors the same
// documented HS256-fallback limitation already present in getJwks().
export async function signIdToken(
  claims: Record<string, unknown>,
  expiresInSeconds: number,
  algorithm: IdTokenSigningAlg = 'HS256',
): Promise<string> {
  if (algorithm === 'RS256') {
    const material = await getCurrentSigningKeyMaterial();
    if (!material || !material.privateKey) {
      throw new Error('OIDC RS256 signing is not configured.');
    }
    return jwt.sign(claims, material.privateKey, {
      algorithm: 'RS256',
      expiresIn: expiresInSeconds,
      keyid: material.kid,
    });
  }

  return jwt.sign(claims, config.JWT_ACCESS_SECRET, {
    algorithm: 'HS256',
    expiresIn: expiresInSeconds,
  });
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// Constant-time comparison of two hex digests of equal expected length.
// Use this (instead of `===`/`!==`) whenever comparing a caller-supplied
// secret's hash against a stored hash, to avoid timing side-channels.
export function timingSafeEqualHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export function generateOpaqueToken(bytes = 32): string {
  return randomBytes(bytes).toString('hex');
}

export function parseTtlToSeconds(ttl: string): number {
  const match = ttl.match(/^(\d+)([smhd])$/);
  if (!match) return 900;
  const n = parseInt(match[1], 10);
  const unit = match[2];
  const mul: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
  return n * mul[unit];
}
