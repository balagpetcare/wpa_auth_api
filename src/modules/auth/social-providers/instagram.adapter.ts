import { OAuthProvider } from '@prisma/client';
import { buildUrl, assertConfigured, type NormalizedSocialProfile, type OAuthExchangeRequest, type SocialProviderAdapter } from './base.js';

export const instagramAdapter: SocialProviderAdapter = {
  provider: OAuthProvider.INSTAGRAM,
  buildAuthorizationUrl(config, state) {
    assertConfigured(config.clientId, 'Instagram client ID is required.');
    return buildUrl(config.authorizationUrl, {
      response_type: 'code',
      client_id: config.clientId ?? undefined,
      redirect_uri: config.redirectUri,
      scope: config.scopes.join(','),
      state,
    });
  },
  async exchangeCodeForToken(config, code, request: OAuthExchangeRequest) {
    assertConfigured(request.clientId, 'Instagram client ID is required.');
    assertConfigured(request.clientSecret, 'Instagram client secret is required.');
    const clientId = request.clientId as string;
    const clientSecret = request.clientSecret as string;
    const body = new URLSearchParams();
    body.set('client_id', clientId);
    body.set('client_secret', clientSecret);
    body.set('grant_type', 'authorization_code');
    body.set('redirect_uri', request.redirectUri);
    body.set('code', code);
    const res = await fetch(config.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body });
    const data = (await res.json().catch(() => ({}))) as { access_token?: string };
    if (!res.ok) throw new Error('Instagram token exchange failed.');
    return String(data.access_token ?? '');
  },
  async fetchProfile(config, accessToken) {
    const res = await fetch(config.userInfoUrl ?? '', { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error('Instagram profile fetch failed.');
    return data as Record<string, unknown>;
  },
  normalizeProfile(rawProfile): NormalizedSocialProfile {
    return {
      provider: OAuthProvider.INSTAGRAM,
      providerUserId: String(rawProfile.id ?? ''),
      displayName: typeof rawProfile.username === 'string' ? rawProfile.username : undefined,
      username: typeof rawProfile.username === 'string' ? rawProfile.username : undefined,
      rawProfile,
    };
  },
};
