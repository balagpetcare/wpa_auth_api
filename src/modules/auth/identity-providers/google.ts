// Google Sign-In via ID token (mobile sends the Google-issued id_token to
// this API; we verify it server-side — no embedded webview, no client
// secret on the mobile app). Verifies signature via Google's official JWKS,
// plus iss/aud/exp. `email_verified` on the token is the ONLY signal we
// trust for email-verified status — see docs/... "never treat a
// provider-supplied email as verified unless the provider says so".
import { OAuthProvider } from '@prisma/client';
import { AppError, ErrorCodes } from '../../../lib/errors.js';
import { config } from '../../../config/index.js';
import { verifyIdToken } from './jwksVerifier.js';
import type { NormalizedIdentityProfile } from './types.js';

const GOOGLE_JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

export function isGoogleLoginEnabled(): boolean {
  return Boolean(config.GOOGLE_LOGIN_AUDIENCE && config.GOOGLE_LOGIN_AUDIENCE.trim());
}

function allowedAudiences(): string[] {
  return (config.GOOGLE_LOGIN_AUDIENCE ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export async function verifyGoogleIdToken(idToken: string): Promise<NormalizedIdentityProfile> {
  if (!isGoogleLoginEnabled()) {
    throw new AppError('Google login is not enabled.', ErrorCodes.PROVIDER_DISABLED, 503);
  }
  const payload = await verifyIdToken(idToken, {
    jwksUri: GOOGLE_JWKS_URI,
    issuer: GOOGLE_ISSUERS,
    audience: allowedAudiences(),
  });
  const sub = typeof payload.sub === 'string' ? payload.sub : '';
  if (!sub) throw new AppError('Google token missing subject.', ErrorCodes.INVALID_PROVIDER_TOKEN, 401);
  return {
    provider: OAuthProvider.GOOGLE,
    providerUserId: sub,
    email: typeof payload.email === 'string' ? payload.email : undefined,
    emailVerified: payload.email_verified === true,
    displayName: typeof payload.name === 'string' ? payload.name : undefined,
    avatarUrl: typeof payload.picture === 'string' ? payload.picture : undefined,
    rawClaims: payload as Record<string, unknown>,
  };
}
