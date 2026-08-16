import { createHmac, timingSafeEqual } from 'crypto';
import { AppError } from './errors.js';

export type MetaSignedRequestPayload = {
  algorithm?: string;
  issued_at?: number;
  expires?: number;
  user_id?: string;
  oauth_token?: string;
  [key: string]: unknown;
};

function base64UrlDecode(value: string) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4;
  const padded = normalized + (pad === 0 ? '' : '='.repeat(4 - pad));
  return Buffer.from(padded, 'base64');
}

export function verifyMetaSignedRequest(
  signedRequest: string,
  appSecret: string,
  nowMs = Date.now(),
): MetaSignedRequestPayload {
  const [encodedSignature, encodedPayload] = signedRequest.split('.', 2);
  if (!encodedSignature || !encodedPayload) {
    throw new AppError('Invalid Meta signed request.', 'VALIDATION_ERROR', 400);
  }
  if (!appSecret) {
    throw new AppError('Meta callback is not configured.', 'PROVIDER_DISABLED', 503);
  }

  const signature = base64UrlDecode(encodedSignature);
  const expected = createHmac('sha256', appSecret).update(encodedPayload).digest();
  if (expected.length !== signature.length || !timingSafeEqual(expected, signature)) {
    throw new AppError('Invalid Meta signed request signature.', 'FORBIDDEN', 403);
  }

  let payload: MetaSignedRequestPayload;
  try {
    payload = JSON.parse(base64UrlDecode(encodedPayload).toString('utf8')) as MetaSignedRequestPayload;
  } catch {
    throw new AppError('Meta signed request payload could not be parsed.', 'VALIDATION_ERROR', 400);
  }

  const algorithm = typeof payload.algorithm === 'string' ? payload.algorithm.toUpperCase() : '';
  if (algorithm !== 'HMAC-SHA256') {
    throw new AppError('Unsupported Meta signed request algorithm.', 'VALIDATION_ERROR', 400);
  }

  if (payload.expires !== undefined) {
    if (!Number.isFinite(payload.expires)) {
      throw new AppError('Meta signed request expiry is invalid.', 'VALIDATION_ERROR', 400);
    }
    if (payload.expires > 0 && payload.expires * 1000 <= nowMs) {
      throw new AppError('Meta signed request has expired.', 'FORBIDDEN', 403);
    }
  }

  if (payload.issued_at !== undefined && !Number.isFinite(payload.issued_at)) {
    throw new AppError('Meta signed request issued_at is invalid.', 'VALIDATION_ERROR', 400);
  }

  return payload;
}
