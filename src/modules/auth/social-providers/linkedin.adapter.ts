import { OAuthProvider, type SocialIdentityProviderConfig } from '@prisma/client';
import { buildUrl, assertConfigured, type NormalizedSocialProfile, type OAuthExchangeRequest, type SocialProviderAdapter } from './base.js';

export const linkedInAdapter: SocialProviderAdapter = {
  provider: OAuthProvider.LINKEDIN,
  buildAuthorizationUrl(config, state) {
    assertConfigured(config.clientId, 'LinkedIn client ID is required.');
    return buildUrl(config.authorizationUrl, {
      response_type: 'code',
      client_id: config.clientId ?? undefined,
      redirect_uri: config.redirectUri,
      scope: config.scopes.join(' '),
      state,
    });
  },
  async exchangeCodeForToken(config, code, request: OAuthExchangeRequest) {
    assertConfigured(request.clientId, 'LinkedIn client ID is required.');
    assertConfigured(request.clientSecret, 'LinkedIn client secret is required.');
    const clientId = request.clientId as string;
    const clientSecret = request.clientSecret as string;
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('code', code);
    body.set('redirect_uri', request.redirectUri);
    body.set('client_id', clientId);
    body.set('client_secret', clientSecret);
    const res = await fetch(config.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body });
    const data = (await res.json().catch(() => ({}))) as { access_token?: string };
    if (!res.ok) throw new Error('LinkedIn token exchange failed.');
    return String(data.access_token ?? '');
  },
  async fetchProfile(config, accessToken) {
    const res = await fetch(config.userInfoUrl ?? '', { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error('LinkedIn profile fetch failed.');
    return data as Record<string, unknown>;
  },
  normalizeProfile(rawProfile): NormalizedSocialProfile {
    return {
      provider: OAuthProvider.LINKEDIN,
      providerUserId: String(rawProfile.sub ?? rawProfile.id ?? ''),
      email: typeof rawProfile.email === 'string' ? rawProfile.email : undefined,
      emailVerified: rawProfile.email_verified === true || rawProfile.email_verified === 'true',
      displayName: typeof rawProfile.name === 'string' ? rawProfile.name : undefined,
      avatarUrl: typeof rawProfile.picture === 'string' ? rawProfile.picture : undefined,
      username: typeof rawProfile.preferred_username === 'string' ? rawProfile.preferred_username : undefined,
      rawProfile,
    };
  },
};
