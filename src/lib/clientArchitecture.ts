import { AuthClientType, OidcIdTokenSigningAlg } from '@prisma/client';
import { AppError } from './errors.js';

export type ClientAuthModel = 'CONFIDENTIAL_WEB' | 'PUBLIC_NATIVE' | 'SERVICE';

export function getClientAuthModel(input: { type: AuthClientType; clientSecretHash: string | null }) {
  if (input.type === 'SERVICE') return 'SERVICE' as const;
  return input.clientSecretHash ? 'CONFIDENTIAL_WEB' as const : 'PUBLIC_NATIVE' as const;
}

function isHttpLike(urlString: string) {
  try {
    const url = new URL(urlString);
    if (url.protocol === 'https:') return true;
    if (url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1')) return true;
    return false;
  } catch {
    return false;
  }
}

function isCustomScheme(urlString: string) {
  try {
    const url = new URL(urlString);
    return url.protocol !== 'http:' && url.protocol !== 'https:';
  } catch {
    return false;
  }
}

export function defaultSigningAlgForClient(type: AuthClientType): OidcIdTokenSigningAlg | null {
  if (type === 'SERVICE') return null;
  return 'RS256';
}

export function normalizeAllowedScopes(type: AuthClientType, allowedScopes?: string[]) {
  if (allowedScopes && allowedScopes.length > 0) return allowedScopes;
  if (type === 'SERVICE') return [];
  return ['openid', 'profile', 'email'];
}

export function validateClientRegistryShape(input: {
  type: AuthClientType;
  allowedOrigins: string[];
  redirectUris: string[];
  clientSecretHash: string | null;
}) {
  if (input.type === 'SERVICE' && !input.clientSecretHash) {
    throw new AppError('SERVICE clients require a client secret.', 'VALIDATION_ERROR', 400);
  }

  const model = getClientAuthModel(input);
  if (model === 'SERVICE') {
    if (input.redirectUris.length > 0) {
      throw new AppError('SERVICE clients must not define redirect URIs.', 'VALIDATION_ERROR', 400);
    }
    if (input.allowedOrigins.length > 0) {
      throw new AppError('SERVICE clients must not define allowed origins.', 'VALIDATION_ERROR', 400);
    }
    return;
  }

  if (model === 'PUBLIC_NATIVE') {
    if (input.allowedOrigins.length > 0) {
      throw new AppError('PUBLIC_NATIVE clients must not define allowed origins.', 'VALIDATION_ERROR', 400);
    }
    if (!input.redirectUris.length) {
      throw new AppError('PUBLIC_NATIVE clients require at least one redirect URI.', 'VALIDATION_ERROR', 400);
    }
    if (!input.redirectUris.every((uri) => isHttpLike(uri) || isCustomScheme(uri))) {
      throw new AppError('PUBLIC_NATIVE clients require at least one custom-scheme or localhost redirect URI.', 'VALIDATION_ERROR', 400);
    }
    return;
  }

  if (!input.allowedOrigins.length) {
    throw new AppError('CONFIDENTIAL_WEB clients require at least one allowed origin.', 'VALIDATION_ERROR', 400);
  }
  if (!input.redirectUris.length) {
    throw new AppError('CONFIDENTIAL_WEB clients require at least one redirect URI.', 'VALIDATION_ERROR', 400);
  }
  if (!input.allowedOrigins.every((origin) => isHttpLike(origin))) {
    throw new AppError('CONFIDENTIAL_WEB clients require HTTPS or localhost allowed origins.', 'VALIDATION_ERROR', 400);
  }
  if (!input.redirectUris.every((uri) => isHttpLike(uri))) {
    throw new AppError('CONFIDENTIAL_WEB clients require HTTPS or localhost redirect URIs.', 'VALIDATION_ERROR', 400);
  }
}
