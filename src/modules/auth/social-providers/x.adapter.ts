import { OAuthProvider } from '@prisma/client';
import crypto from 'crypto';
import { buildUrl, assertConfigured, type NormalizedSocialProfile, type OAuthExchangeRequest, type SocialProviderAdapter } from './base.js';

export const xAdapter: SocialProviderAdapter = {
  provider: OAuthProvider.X,
  requiresPkce: true,
  buildAuthorizationUrl(config, state) {
    assertConfigured(config.clientId, 'X client ID is required.');
    return buildUrl(config.authorizationUrl, {
      response_type: 'code',
      client_id: config.clientId ?? undefined,
      redirect_uri: config.redirectUri,
      scope: config.scopes.join(' '),
      state,
      code_challenge_method: 'S256',
    });
  },
  async exchangeCodeForToken(config, code, request: OAuthExchangeRequest) {
    assertConfigured(request.clientId, 'X client ID is required.');
    assertConfigured(request.clientSecret, 'X client secret is required.');
    assertConfigured(request.codeVerifier, 'X PKCE code verifier is required.');
    const clientId = request.clientId as string;
    const codeVerifier = request.codeVerifier as string;
    const clientSecret = request.clientSecret as string;
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('code', code);
    body.set('redirect_uri', request.redirectUri);
    body.set('client_id', clientId);
    body.set('code_verifier', codeVerifier);
    const basic = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    const res = await fetch(config.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', Authorization: `Basic ${basic}` }, body });
    const data = (await res.json().catch(() => ({}))) as { access_token?: string };
    if (!res.ok) throw new Error('X token exchange failed.');
    return String(data.access_token ?? '');
  },
  async fetchProfile(config, accessToken) {
    const res = await fetch(config.userInfoUrl ?? '', { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error('X profile fetch failed.');
    return data as Record<string, unknown>;
  },
  normalizeProfile(rawProfile): NormalizedSocialProfile {
    const user = (rawProfile.data as Record<string, unknown> | undefined) ?? rawProfile;
    return {
      provider: OAuthProvider.X,
      providerUserId: String(user.id ?? rawProfile.id ?? ''),
      email: typeof user.email === 'string' ? user.email : undefined,
      displayName: typeof user.name === 'string' ? user.name : undefined,
      avatarUrl: typeof user.profile_image_url === 'string' ? user.profile_image_url : undefined,
      username: typeof user.username === 'string' ? user.username : undefined,
      rawProfile,
    };
  },
};
