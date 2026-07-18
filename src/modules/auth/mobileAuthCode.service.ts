// Single-use, PKCE-bound authorization codes for mobile social/enterprise
// login completion (see MobileAuthorizationCode in prisma/schema.prisma).
//
// Why: redirecting access/refresh tokens through a custom-scheme URI (even
// in the fragment) exposes them to any app that can register the scheme and
// to OS-level intent logging. Instead the callback now hands the app an
// opaque, short-lived code; the app exchanges it at POST /auth/mobile/token
// with the PKCE code_verifier it generated before the flow started. Only
// the app instance that initiated the flow can complete it.
//
// The raw code is never persisted or logged — only its SHA-256 hash.
import crypto from 'crypto';
import { prisma } from '../../lib/db.js';
import { AppError } from '../../lib/errors.js';
import { encryptCredentialPayload, decryptCredentialPayloadByVersion } from '../../lib/credentialEncryption.js';

export const MOBILE_AUTH_CODE_TTL_SECONDS = 60;

export type MobileSessionPayload = {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
};

export function hashAuthCode(code: string): string {
  return crypto.createHash('sha256').update(code).digest('hex');
}

/// Pure PKCE S256 check: base64url(sha256(verifier)) === challenge.
export function verifyPkceS256(codeVerifier: string, codeChallenge: string): boolean {
  if (!codeVerifier || codeVerifier.length < 43 || codeVerifier.length > 128) return false;
  const computed = crypto.createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
  const a = Buffer.from(computed);
  const b = Buffer.from(codeChallenge);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export async function issueMobileAuthCode(opts: {
  clientDbId: string;
  redirectUri: string;
  codeChallenge: string;
  session: MobileSessionPayload;
}): Promise<string> {
  const code = crypto.randomBytes(32).toString('base64url');
  const encrypted = encryptCredentialPayload({ ...opts.session });
  await prisma.mobileAuthorizationCode.create({
    data: {
      codeHash: hashAuthCode(code),
      clientDbId: opts.clientDbId,
      redirectUri: opts.redirectUri,
      codeChallenge: opts.codeChallenge,
      payloadEncrypted: JSON.stringify(encrypted),
      expiresAt: new Date(Date.now() + MOBILE_AUTH_CODE_TTL_SECONDS * 1000),
    },
  });
  return code;
}

export async function exchangeMobileAuthCode(opts: {
  code: string;
  codeVerifier: string;
  clientId: string; // public AuthClient.clientId, e.g. "furtail-mobile"
  redirectUri: string;
}): Promise<MobileSessionPayload> {
  const row = await prisma.mobileAuthorizationCode.findUnique({
    where: { codeHash: hashAuthCode(opts.code) },
  });
  if (!row) {
    throw new AppError('Invalid authorization code.', 'AUTH_CODE_INVALID', 400);
  }
  if (row.consumedAt) {
    // Reuse is a theft signal — the code stays consumed and nothing is
    // returned. (The tokens inside were already handed out once; session
    // revocation on reuse is handled by refresh-token rotation upstream.)
    throw new AppError('Authorization code already used.', 'AUTH_CODE_REUSED', 400);
  }
  if (row.expiresAt.getTime() < Date.now()) {
    throw new AppError('Authorization code expired.', 'AUTH_CODE_EXPIRED', 400);
  }

  const client = await prisma.authClient.findUnique({ where: { clientId: opts.clientId } });
  if (!client || client.status !== 'ACTIVE' || client.id !== row.clientDbId) {
    throw new AppError('Authorization code was not issued to this client.', 'AUTH_CODE_INVALID', 400);
  }
  if (opts.redirectUri !== row.redirectUri) {
    throw new AppError('redirect_uri does not match the authorization request.', 'AUTH_CODE_INVALID', 400);
  }
  if (!verifyPkceS256(opts.codeVerifier, row.codeChallenge)) {
    throw new AppError('PKCE verification failed.', 'PKCE_VERIFICATION_FAILED', 400);
  }

  // Single-use: consume atomically before releasing the payload; a
  // concurrent second exchange loses the updateMany race and gets REUSED.
  const consumed = await prisma.mobileAuthorizationCode.updateMany({
    where: { id: row.id, consumedAt: null },
    data: { consumedAt: new Date() },
  });
  if (consumed.count === 0) {
    throw new AppError('Authorization code already used.', 'AUTH_CODE_REUSED', 400);
  }

  const encrypted = JSON.parse(row.payloadEncrypted);
  const payload = decryptCredentialPayloadByVersion(encrypted, encrypted.version);
  return {
    accessToken: String(payload.accessToken),
    refreshToken: String(payload.refreshToken),
    expiresIn: Number(payload.expiresIn),
  };
}
