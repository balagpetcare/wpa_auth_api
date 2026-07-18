// Shared JWKS-based id_token verification helper. Every OIDC-style adapter
// (google.ts, apple.ts, microsoft.ts, enterprise-oidc.ts) uses this instead
// of decoding the JWT payload unverified — `jose`'s createRemoteJWKSet +
// jwtVerify fetches the provider's published JWKS (with in-process
// caching/rotation handling built into `jose`) and verifies the RS256/ES256
// signature, `iss`, `aud`, and `exp` before we ever look at any claim.
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { AppError, ErrorCodes } from '../../../lib/errors.js';
import { logger } from '../../../lib/logger.js';

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(jwksUri: string) {
  let jwks = jwksCache.get(jwksUri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri), {
      cacheMaxAge: 10 * 60 * 1000,
      cooldownDuration: 30 * 1000,
    });
    jwksCache.set(jwksUri, jwks);
  }
  return jwks;
}

export type VerifyIdTokenOptions = {
  jwksUri: string;
  // Omit only for multi-tenant "meta" issuers (e.g. Microsoft's
  // common/organizations/consumers endpoints) where the caller validates
  // the issuer shape itself after verification — see microsoft.ts.
  issuer?: string | string[];
  audience: string | string[];
  /** Optional expected nonce (checked if the caller supplies one). */
  nonce?: string;
  clockToleranceSeconds?: number;
};

/**
 * Verifies an id_token's signature against the provider's live JWKS, plus
 * iss/aud/exp (and nonce, if supplied). Never trusts the payload without
 * this. Throws AppError(INVALID_PROVIDER_TOKEN) on any failure — signature
 * mismatch, expired token, wrong issuer/audience, or unreachable JWKS.
 */
export async function verifyIdToken(idToken: string, opts: VerifyIdTokenOptions): Promise<JWTPayload> {
  try {
    const jwks = getJwks(opts.jwksUri);
    const { payload } = await jwtVerify(idToken, jwks, {
      ...(opts.issuer !== undefined ? { issuer: opts.issuer } : {}),
      audience: opts.audience,
      clockTolerance: opts.clockToleranceSeconds ?? 60,
    });
    if (opts.nonce !== undefined) {
      if (payload.nonce !== opts.nonce) {
        throw new Error('nonce mismatch');
      }
    }
    return payload;
  } catch (err) {
    logger.warn(
      { error: err instanceof Error ? err.message : String(err), jwksUri: opts.jwksUri },
      'Identity provider id_token verification failed',
    );
    throw new AppError('The provider token is invalid or could not be verified.', ErrorCodes.INVALID_PROVIDER_TOKEN, 401);
  }
}
