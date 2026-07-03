import crypto from 'crypto';
import { AppError } from '../../../lib/errors.js';
import { config } from '../../../config/index.js';
import type { OAuthProvider, SocialIdentityProviderConfig } from '@prisma/client';

export type OAuthRedirectContext = Record<string, string | undefined>;

export type OAuthExchangeRequest = {
  redirectUri: string;
  codeVerifier?: string;
  clientId: string;
  clientSecret?: string;
};

export type NormalizedSocialProfile = {
  provider: OAuthProvider;
  providerUserId: string;
  email?: string;
  emailVerified?: boolean;
  displayName?: string;
  avatarUrl?: string;
  username?: string;
  rawProfile: Record<string, unknown>;
};

export type SocialProviderAdapter = {
  provider: OAuthProvider;
  requiresPkce?: boolean;
  buildAuthorizationUrl: (config: SocialIdentityProviderConfig, state: string, redirectContext?: OAuthRedirectContext) => string;
  exchangeCodeForToken: (config: SocialIdentityProviderConfig, code: string, request: OAuthExchangeRequest) => Promise<string>;
  fetchProfile: (config: SocialIdentityProviderConfig, accessToken: string) => Promise<Record<string, unknown>>;
  normalizeProfile: (rawProfile: Record<string, unknown>) => NormalizedSocialProfile;
};

export function assertConfigured(value: string | null | undefined, message: string, code = 'PROVIDER_MISCONFIGURED') {
  if (!value || !value.trim()) throw new AppError(message, code, 400);
}

export function buildUrl(base: string, params: Record<string, string | undefined | null>) {
  const url = new URL(base);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') url.searchParams.set(key, value);
  }
  return url.toString();
}

export function buildStateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

export function appCallbackUrl(provider: OAuthProvider) {
  return `${config.APP_URL.replace(/\/$/, '')}/api/v1/auth/social/${provider.toLowerCase()}/callback`;
}

export function safeString(value: unknown) {
  return typeof value === 'string' ? value : '';
}
