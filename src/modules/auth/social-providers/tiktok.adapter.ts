import { OAuthProvider } from '@prisma/client';
import { buildUrl, assertConfigured, type NormalizedSocialProfile, type OAuthExchangeRequest, type SocialProviderAdapter } from './base.js';

export const tiktokAdapter: SocialProviderAdapter = {
  provider: OAuthProvider.TIKTOK,
  buildAuthorizationUrl(config, state) {
    assertConfigured(config.clientId, 'TikTok client ID is required.');
    return buildUrl(config.authorizationUrl, {
      response_type: 'code',
      client_key: config.clientId ?? undefined,
      redirect_uri: config.redirectUri,
      scope: config.scopes.join(','),
      state,
    });
  },
  async exchangeCodeForToken(config, code, request: OAuthExchangeRequest) {
    assertConfigured(request.clientId, 'TikTok client ID is required.');
    assertConfigured(request.clientSecret, 'TikTok client secret is required.');
    const clientId = request.clientId as string;
    const clientSecret = request.clientSecret as string;
    const body = new URLSearchParams();
    body.set('client_key', clientId);
    body.set('client_secret', clientSecret);
    body.set('code', code);
    body.set('grant_type', 'authorization_code');
    body.set('redirect_uri', request.redirectUri);
    const res = await fetch(config.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body });
    const data = (await res.json().catch(() => ({}))) as { access_token?: string };
    if (!res.ok) throw new Error('TikTok token exchange failed.');
    return String(data.access_token ?? '');
  },
  async fetchProfile(config, accessToken) {
    const res = await fetch(config.userInfoUrl ?? '', { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error('TikTok profile fetch failed.');
    return data as Record<string, unknown>;
  },
  normalizeProfile(rawProfile): NormalizedSocialProfile {
    const user = (rawProfile.user as Record<string, unknown> | undefined) ?? rawProfile;
    return {
      provider: OAuthProvider.TIKTOK,
      providerUserId: String(user.open_id ?? user.id ?? rawProfile.open_id ?? rawProfile.id ?? ''),
      email: typeof user.email === 'string' ? user.email : undefined,
      emailVerified: typeof user.email === 'string' ? undefined : undefined,
      displayName: typeof user.display_name === 'string' ? user.display_name : undefined,
      avatarUrl: typeof user.avatar_url === 'string' ? user.avatar_url : undefined,
      username: typeof user.username === 'string' ? user.username : undefined,
      rawProfile,
    };
  },
};
