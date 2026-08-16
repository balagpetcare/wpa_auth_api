// Facebook login: the mobile app sends a Facebook-issued USER access token
// (from the native Facebook SDK, no embedded webview) to this API. Facebook
// has no id_token/JWKS to verify against, so we verify the token server-side
// via the Graph API `debug_token` endpoint (using our app access token —
// app_id + app_secret, both server-only, never sent to the client) and
// confirm it belongs to our own app and is still valid, then fetch /me.
//
// Facebook never asserts email verification — the `email` field on /me is
// only returned for accounts with a confirmed email on Facebook's side, but
// Facebook's API does NOT expose a verification flag we can check, so per
// the hard rule in the audit doc we treat every Facebook email as
// UNVERIFIED. This means a Facebook-only first login can never
// auto-link/auto-merge into an existing verified-email account — it always
// creates a new user or requires explicit linking.
import { OAuthProvider } from '@prisma/client';
import { AppError, ErrorCodes } from '../../../lib/errors.js';
import { config } from '../../../config/index.js';
import { logger } from '../../../lib/logger.js';
import type { NormalizedIdentityProfile } from './types.js';
import { resolveFacebookAppCredentials, getFacebookGraphApiVersion } from '../facebookMetaConfig.js';

export function isFacebookLoginEnabled(): boolean {
  return Boolean(config.FACEBOOK_APP_ID && config.FACEBOOK_APP_SECRET);
}

type DebugTokenResponse = {
  data?: {
    app_id?: string;
    is_valid?: boolean;
    user_id?: string;
    error?: { message?: string };
  };
};

export async function verifyFacebookAccessToken(userAccessToken: string): Promise<NormalizedIdentityProfile> {
  const credentials = await resolveFacebookAppCredentials();
  if (!credentials) {
    throw new AppError('Facebook login is not enabled.', ErrorCodes.PROVIDER_DISABLED, 503);
  }
  const { appId, appSecret } = credentials;
  const appAccessToken = `${appId}|${appSecret}`;

  let debug: DebugTokenResponse;
  try {
    const debugUrl = new URL(`https://graph.facebook.com/${getFacebookGraphApiVersion()}/debug_token`);
    debugUrl.searchParams.set('input_token', userAccessToken);
    debugUrl.searchParams.set('access_token', appAccessToken);
    const res = await fetch(debugUrl.toString());
    debug = (await res.json()) as DebugTokenResponse;
    if (!res.ok || !debug.data) throw new Error('debug_token request failed');
  } catch (err) {
    logger.warn({ error: err instanceof Error ? err.message : String(err) }, 'Facebook debug_token verification failed');
    throw new AppError('The Facebook token is invalid or could not be verified.', ErrorCodes.INVALID_PROVIDER_TOKEN, 401);
  }

  if (!debug.data.is_valid || debug.data.app_id !== appId || !debug.data.user_id) {
    throw new AppError('The Facebook token is invalid or does not belong to this app.', ErrorCodes.INVALID_PROVIDER_TOKEN, 401);
  }

  const meUrl = new URL(`https://graph.facebook.com/${getFacebookGraphApiVersion()}/me`);
  meUrl.searchParams.set('fields', 'id,name,email,picture');
  meUrl.searchParams.set('access_token', userAccessToken);
  const meRes = await fetch(meUrl.toString());
  const me = (await meRes.json()) as { id?: string; name?: string; email?: string; picture?: { data?: { url?: string } } };
  if (!meRes.ok || !me.id || me.id !== debug.data.user_id) {
    throw new AppError('Failed to load the Facebook profile for this token.', ErrorCodes.INVALID_PROVIDER_TOKEN, 401);
  }

  return {
    provider: OAuthProvider.FACEBOOK,
    providerUserId: me.id,
    email: me.email,
    emailVerified: false, // see module doc comment: Facebook never asserts this
    displayName: me.name,
    avatarUrl: me.picture?.data?.url,
    rawClaims: me as Record<string, unknown>,
  };
}
