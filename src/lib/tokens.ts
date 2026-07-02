import jwt from 'jsonwebtoken';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import { config } from '../config/index.js';

export interface AccessTokenPayload {
  sub: string;
  email: string | null;
  username: string | null;
  roles: string[];
}

export function signAccessToken(payload: AccessTokenPayload): string {
  return jwt.sign(payload, config.JWT_ACCESS_SECRET, {
    expiresIn: config.ACCESS_TOKEN_TTL as any,
  });
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  return jwt.verify(token, config.JWT_ACCESS_SECRET) as AccessTokenPayload;
}

export function signRefreshToken(userId: string): string {
  const jti = randomBytes(16).toString('hex');
  return jwt.sign({ sub: userId, jti }, config.JWT_REFRESH_SECRET, {
    expiresIn: config.REFRESH_TOKEN_TTL as any,
  });
}

export function verifyRefreshToken(token: string): { sub: string } {
  return jwt.verify(token, config.JWT_REFRESH_SECRET) as { sub: string };
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
export function signIdToken(claims: Record<string, unknown>, expiresInSeconds: number): string {
  if (config.JWT_RSA_PRIVATE_KEY) {
    const privateKey = config.JWT_RSA_PRIVATE_KEY.replace(/\\n/g, '\n');
    return jwt.sign(claims, privateKey, {
      algorithm: 'RS256',
      expiresIn: expiresInSeconds,
      keyid: config.JWT_KEY_ID,
    });
  }

  console.warn(
    '[OIDC] JWT_RSA_PRIVATE_KEY not configured — signing id_token with HS256 as a local-development-only fallback. ' +
      'This id_token CANNOT be verified by a third party against /oauth/jwks (HS256 is symmetric). ' +
      'Set JWT_RSA_PRIVATE_KEY and JWT_RSA_PUBLIC_KEY for standards-compliant OIDC.',
  );
  return jwt.sign(claims, config.JWT_ACCESS_SECRET, {
    algorithm: 'HS256',
    expiresIn: expiresInSeconds,
    keyid: config.JWT_KEY_ID,
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
