// Sign in with Apple, via identity token verification against Apple's JWKS
// (https://appleid.apple.com/auth/keys). Checks iss=https://appleid.apple.com,
// aud=configured Services ID / bundle id(s), exp, signature, and nonce when
// the caller supplies one. Apple's `email_verified` claim (a boolean OR the
// string "true"/"false" depending on client SDK version) is the only signal
// trusted for verified-email status.
import { OAuthProvider } from '@prisma/client';
import { AppError, ErrorCodes } from '../../../lib/errors.js';
import { config } from '../../../config/index.js';
import { verifyIdToken } from './jwksVerifier.js';
import type { NormalizedIdentityProfile } from './types.js';

const APPLE_JWKS_URI = 'https://appleid.apple.com/auth/keys';
const APPLE_ISSUER = 'https://appleid.apple.com';

export function isAppleLoginEnabled(): boolean {
  return Boolean(config.APPLE_LOGIN_AUDIENCE && config.APPLE_LOGIN_AUDIENCE.trim());
}

function allowedAudiences(): string[] {
  return (config.APPLE_LOGIN_AUDIENCE ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function truthy(value: unknown) {
  return value === true || value === 'true';
}

export async function verifyAppleIdToken(idToken: string, opts?: { nonce?: string }): Promise<NormalizedIdentityProfile> {
  if (!isAppleLoginEnabled()) {
    throw new AppError('Apple login is not enabled.', ErrorCodes.PROVIDER_DISABLED, 503);
  }
  const payload = await verifyIdToken(idToken, {
    jwksUri: APPLE_JWKS_URI,
    issuer: APPLE_ISSUER,
    audience: allowedAudiences(),
    nonce: opts?.nonce,
  });
  const sub = typeof payload.sub === 'string' ? payload.sub : '';
  if (!sub) throw new AppError('Apple token missing subject.', ErrorCodes.INVALID_PROVIDER_TOKEN, 401);
  return {
    provider: OAuthProvider.APPLE,
    providerUserId: sub,
    email: typeof payload.email === 'string' ? payload.email : undefined,
    emailVerified: truthy(payload.email_verified),
    // Apple never puts name in the id_token — the app must send the
    // one-time `fullName` it gets from ASAuthorizationAppleIDCredential on
    // FIRST sign-in only; nothing to normalize here from the token itself.
    rawClaims: payload as Record<string, unknown>,
  };
}
