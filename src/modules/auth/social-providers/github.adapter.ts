import { OAuthProvider } from '@prisma/client';
import { buildUrl, assertConfigured, type NormalizedSocialProfile, type OAuthExchangeRequest, type SocialProviderAdapter } from './base.js';

export const githubAdapter: SocialProviderAdapter = {
  provider: OAuthProvider.GITHUB,
  buildAuthorizationUrl(config, state) {
    assertConfigured(config.clientId, 'GitHub client ID is required.');
    return buildUrl(config.authorizationUrl, {
      response_type: 'code',
      client_id: config.clientId ?? undefined,
      redirect_uri: config.redirectUri,
      scope: config.scopes.join(' '),
      state,
      allow_signup: 'true',
    });
  },
  async exchangeCodeForToken(config, code, request: OAuthExchangeRequest) {
    assertConfigured(request.clientId, 'GitHub client ID is required.');
    assertConfigured(request.clientSecret, 'GitHub client secret is required.');
    const clientId = request.clientId as string;
    const clientSecret = request.clientSecret as string;
    const body = new URLSearchParams();
    body.set('code', code);
    body.set('client_id', clientId);
    body.set('client_secret', clientSecret);
    body.set('redirect_uri', request.redirectUri);
    const res = await fetch(config.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body });
    const data = (await res.json().catch(() => ({}))) as { access_token?: string };
    if (!res.ok) throw new Error('GitHub token exchange failed.');
    return String(data.access_token ?? '');
  },
  async fetchProfile(config, accessToken) {
    const headers = { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' };
    const profileRes = await fetch(config.userInfoUrl ?? '', { headers });
    const profile = await profileRes.json().catch(() => ({}));
    if (!profileRes.ok) throw new Error('GitHub profile fetch failed.');
    let emails: Record<string, unknown>[] = [];
    try {
      const emailRes = await fetch('https://api.github.com/user/emails', { headers });
      if (emailRes.ok) emails = (await emailRes.json().catch(() => [])) as Record<string, unknown>[];
    } catch {
      emails = [];
    }
    return { ...(profile as Record<string, unknown>), _emails: emails };
  },
  normalizeProfile(rawProfile): NormalizedSocialProfile {
    const emails = Array.isArray(rawProfile._emails) ? rawProfile._emails : [];
    const primary = emails.find((email) => email.primary === true) ?? emails.find((email) => email.verified === true) ?? emails[0];
    return {
      provider: OAuthProvider.GITHUB,
      providerUserId: String(rawProfile.id ?? ''),
      email: typeof rawProfile.email === 'string' ? rawProfile.email : (typeof primary?.email === 'string' ? primary.email : undefined),
      emailVerified: typeof rawProfile.email === 'string' ? Boolean(rawProfile.email) : (typeof primary?.verified === 'boolean' ? primary.verified : undefined),
      displayName: typeof rawProfile.name === 'string' ? rawProfile.name : undefined,
      avatarUrl: typeof rawProfile.avatar_url === 'string' ? rawProfile.avatar_url : undefined,
      username: typeof rawProfile.login === 'string' ? rawProfile.login : undefined,
      rawProfile,
    };
  },
};
