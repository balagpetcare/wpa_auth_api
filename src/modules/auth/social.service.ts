import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { OAuthProvider, SocialIdentityProviderEnvironment, SocialIdentityProviderPlacement, SocialIdentityProviderStatus, UserStatus } from '@prisma/client';
import { prisma } from '../../lib/db.js';
import { AppError } from '../../lib/errors.js';
import { config } from '../../config/index.js';
import { decryptCredentialPayload, encryptCredentialPayload } from '../../lib/credentialEncryption.js';
import { writeAuditLog } from '../../lib/audit.js';
import { hashToken, parseTtlToSeconds, generateOpaqueToken, signAccessToken, signRefreshToken } from '../../lib/tokens.js';
import type { Request } from 'express';
import { appCallbackUrl, buildStateNonce, githubAdapter, instagramAdapter, linkedInAdapter, tiktokAdapter, xAdapter, type NormalizedSocialProfile, type SocialProviderAdapter } from './social-providers/index.js';

type ProviderProfile = NormalizedSocialProfile;
type SocialCallbackResult =
  | { kind: 'LOGIN'; accessToken: string; refreshToken: string; expiresIn: number; user: { id: string; email: string | null; displayName: string | null; avatarUrl: string | null; roles: string[] } }
  | { kind: 'EMAIL_REQUIRED'; provider: OAuthProvider; completionToken: string; message: string };

const adapterMap: Record<OAuthProvider, SocialProviderAdapter | undefined> = {
  GOOGLE: undefined,
  FACEBOOK: undefined,
  APPLE: undefined,
  MICROSOFT: undefined,
  LINKEDIN: linkedInAdapter,
  TIKTOK: tiktokAdapter,
  X: xAdapter,
  GITHUB: githubAdapter,
  INSTAGRAM: instagramAdapter,
};

const DEFAULT_PROVIDER_META: Record<OAuthProvider, { displayName: string; placement: SocialIdentityProviderPlacement; sortOrder: number }> = {
  GOOGLE: { displayName: 'Google', placement: SocialIdentityProviderPlacement.MAIN, sortOrder: 1 },
  FACEBOOK: { displayName: 'Facebook', placement: SocialIdentityProviderPlacement.MAIN, sortOrder: 2 },
  APPLE: { displayName: 'Apple', placement: SocialIdentityProviderPlacement.MAIN, sortOrder: 3 },
  MICROSOFT: { displayName: 'Microsoft', placement: SocialIdentityProviderPlacement.MAIN, sortOrder: 4 },
  LINKEDIN: { displayName: 'LinkedIn', placement: SocialIdentityProviderPlacement.MORE, sortOrder: 5 },
  TIKTOK: { displayName: 'TikTok', placement: SocialIdentityProviderPlacement.MORE, sortOrder: 6 },
  X: { displayName: 'X', placement: SocialIdentityProviderPlacement.MORE, sortOrder: 7 },
  GITHUB: { displayName: 'GitHub', placement: SocialIdentityProviderPlacement.MORE, sortOrder: 8 },
  INSTAGRAM: { displayName: 'Instagram', placement: SocialIdentityProviderPlacement.MORE, sortOrder: 9 },
};

function normalizeProvider(provider: string): OAuthProvider {
  const upper = provider.toUpperCase();
  if (Object.values(OAuthProvider).includes(upper as OAuthProvider)) return upper as OAuthProvider;
  throw new AppError('Unsupported provider.', 'INVALID_PROVIDER', 400);
}

function buildDefaultConfig(provider: OAuthProvider) {
  const meta = DEFAULT_PROVIDER_META[provider];
  const callbackUrl = appCallbackUrl(provider);
  const endpoints: Record<OAuthProvider, { authorizationUrl: string; tokenUrl: string; userInfoUrl?: string; scopes: string[] }> = {
    GOOGLE: { authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth', tokenUrl: 'https://oauth2.googleapis.com/token', userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo', scopes: ['openid', 'email', 'profile'] },
    FACEBOOK: { authorizationUrl: 'https://www.facebook.com/v19.0/dialog/oauth', tokenUrl: 'https://graph.facebook.com/v19.0/oauth/access_token', userInfoUrl: 'https://graph.facebook.com/me?fields=id,name,email,picture', scopes: ['email', 'public_profile'] },
    APPLE: { authorizationUrl: 'https://appleid.apple.com/auth/authorize', tokenUrl: 'https://appleid.apple.com/auth/token', scopes: ['name', 'email'] },
    MICROSOFT: { authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token', userInfoUrl: 'https://graph.microsoft.com/oidc/userinfo', scopes: ['openid', 'email', 'profile', 'offline_access'] },
    LINKEDIN: { authorizationUrl: 'https://www.linkedin.com/oauth/v2/authorization', tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken', userInfoUrl: 'https://api.linkedin.com/v2/userinfo', scopes: ['openid', 'profile', 'email'] },
    TIKTOK: { authorizationUrl: 'https://www.tiktok.com/v2/auth/authorize/', tokenUrl: 'https://open.tiktokapis.com/v2/oauth/token/', userInfoUrl: 'https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name', scopes: ['user.info.basic'] },
    X: { authorizationUrl: 'https://twitter.com/i/oauth2/authorize', tokenUrl: 'https://api.x.com/2/oauth2/token', userInfoUrl: 'https://api.x.com/2/users/me?user.fields=profile_image_url', scopes: ['tweet.read', 'users.read', 'offline.access'] },
    GITHUB: { authorizationUrl: 'https://github.com/login/oauth/authorize', tokenUrl: 'https://github.com/login/oauth/access_token', userInfoUrl: 'https://api.github.com/user', scopes: ['read:user', 'user:email'] },
    INSTAGRAM: { authorizationUrl: 'https://api.instagram.com/oauth/authorize', tokenUrl: 'https://api.instagram.com/oauth/access_token', userInfoUrl: 'https://graph.instagram.com/me?fields=id,username', scopes: ['user_profile'] },
  };
  return {
    provider,
    displayName: meta.displayName,
    clientId: null,
    clientSecretEncrypted: null,
    redirectUri: callbackUrl,
    environment: SocialIdentityProviderEnvironment.LIVE,
    placement: meta.placement,
    sortOrder: meta.sortOrder,
    showOnLogin: true,
    status: SocialIdentityProviderStatus.INACTIVE,
    ...endpoints[provider],
  };
}

async function getConfig(provider: OAuthProvider) {
  const existing = await prisma.socialIdentityProviderConfig.findUnique({ where: { provider } });
  if (existing) return existing;
  return prisma.socialIdentityProviderConfig.create({ data: buildDefaultConfig(provider) });
}

function decryptSecret(secret: string) {
  return decryptCredentialPayload(JSON.parse(secret)) as { clientSecret?: string };
}

function getAdapter(provider: OAuthProvider) {
  return adapterMap[provider];
}

function asString(value: unknown) {
  return typeof value === 'string' ? value : undefined;
}

function asBool(value: unknown) {
  return value === true || value === 'true';
}

function asRecord(value: unknown) {
  return value && typeof value === 'object' ? value as Record<string, unknown> : {};
}

function sanitizeProfile(profile: ProviderProfile) {
  return {
    provider: profile.provider,
    providerUserId: profile.providerUserId,
    email: profile.email ? '[redacted]' : undefined,
    emailVerified: profile.emailVerified,
    displayName: profile.displayName,
    username: profile.username,
    hasAvatar: Boolean(profile.avatarUrl),
  };
}

function signSocialEmailCompletionToken(data: { provider: OAuthProvider; providerUserId: string; redirectContext?: Record<string, string | undefined>; email?: string; code?: string }) {
  return jwt.sign(
    { ...data, purpose: 'SOCIAL_EMAIL_COMPLETION' },
    config.JWT_ACCESS_SECRET,
    { expiresIn: '15m' },
  );
}

async function resolveProfile(provider: OAuthProvider, accessToken: string, row: Awaited<ReturnType<typeof getConfig>>) {
  const adapter = getAdapter(provider);
  if (adapter) {
    const raw = await adapter.fetchProfile(row, accessToken);
    return adapter.normalizeProfile(raw);
  }
  if (!row.userInfoUrl) {
    throw new AppError(`Provider ${provider} needs a userInfoUrl before sign-in can work.`, 'PROVIDER_MISCONFIGURED', 400);
  }
  const res = await fetch(row.userInfoUrl, { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
  const data = asRecord(await res.json());
  if (!res.ok) throw new AppError(`Failed to load ${provider} profile.`, 'PROVIDER_ERROR', 502);
  if (provider === 'GOOGLE' || provider === 'MICROSOFT' || provider === 'APPLE') return { provider, providerUserId: String(data.sub ?? data.id ?? ''), email: asString(data.email), emailVerified: asBool(data.email_verified), displayName: asString(data.name), avatarUrl: asString(data.picture), rawProfile: data };
  if (provider === 'FACEBOOK') return { provider, providerUserId: String(data.id ?? ''), email: asString(data.email), emailVerified: Boolean(data.email), displayName: asString(data.name), avatarUrl: asString((data.picture as Record<string, unknown> | undefined)?.['data']), rawProfile: data };
  return { provider, providerUserId: String(data.id ?? data.sub ?? ''), email: asString(data.email), displayName: asString(data.name) ?? asString(data.username), avatarUrl: asString(data.avatar_url), rawProfile: data };
}

async function loginOrLink(provider: OAuthProvider, profile: ProviderProfile, clientId: string, req: Request, redirectContext?: Record<string, string | undefined>): Promise<SocialCallbackResult> {
  if (!profile.providerUserId) throw new AppError('Provider returned an invalid profile.', 'PROVIDER_ERROR', 502);
  const existingAccount = await prisma.oAuthAccount.findUnique({ where: { provider_providerAccountId: { provider, providerAccountId: profile.providerUserId } }, include: { user: true } });
  let user = existingAccount?.user;
  if (!user && profile.email && profile.emailVerified) {
    user = await prisma.user.findFirst({ where: { email: profile.email, emailVerifiedAt: { not: null } } }) ?? undefined;
  }
  if (!user && !profile.email) {
    return {
      kind: 'EMAIL_REQUIRED',
      provider,
      completionToken: signSocialEmailCompletionToken({
        provider,
        providerUserId: profile.providerUserId,
        redirectContext,
      }),
      message: 'This provider did not return an email address. Please add an email to continue.',
    };
  }
  if (!user) {
    user = await prisma.user.create({
      data: {
        email: profile.email,
        displayName: profile.displayName,
        avatarUrl: profile.avatarUrl,
        emailVerifiedAt: profile.emailVerified ? new Date() : null,
        status: UserStatus.ACTIVE,
        registrationSource: `social:${provider}`,
      },
    });
    const defaultRole = await prisma.role.findFirst({ where: { name: { in: ['USER', 'user'] } } });
    if (defaultRole) await prisma.userRole.create({ data: { userId: user.id, roleId: defaultRole.id } });
  }
  if (!existingAccount) {
    await prisma.oAuthAccount.create({ data: { userId: user.id, provider, providerAccountId: profile.providerUserId, rawProfile: sanitizeProfile(profile) } });
  }
  const rolesRows = await prisma.userRole.findMany({ where: { userId: user.id }, include: { role: true } });
  const roles = rolesRows.map((r) => r.role.name);
  const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username, roles });
  const refreshToken = signRefreshToken(user.id);
  await prisma.loginSession.create({ data: { userId: user.id, clientId, sessionToken: generateOpaqueToken(), expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000), ipAddress: req.ip ?? req.socket.remoteAddress, userAgent: req.headers['user-agent'] } });
  await prisma.refreshToken.create({ data: { userId: user.id, clientId, tokenHash: hashToken(refreshToken), scopes: ['openid', 'offline_access'], expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000), ipAddress: req.ip ?? req.socket.remoteAddress, userAgent: req.headers['user-agent'], familyId: user.id } });
  await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  await writeAuditLog({ userId: user.id, clientId, action: 'LOGIN', metadata: { method: 'social', provider }, req });
  return { kind: 'LOGIN', accessToken, refreshToken, expiresIn: parseTtlToSeconds(config.ACCESS_TOKEN_TTL), user: { id: user.id, email: user.email, displayName: user.displayName, avatarUrl: user.avatarUrl, roles } };
}

export async function listPublicProviders() {
  const rows = await prisma.socialIdentityProviderConfig.findMany({ where: { status: SocialIdentityProviderStatus.ACTIVE, showOnLogin: true }, orderBy: [{ placement: 'asc' }, { sortOrder: 'asc' }, { displayName: 'asc' }] });
  const grouped = { main: [] as Array<Record<string, unknown>>, more: [] as Array<Record<string, unknown>> };
  for (const row of rows) {
    const item = { id: row.id, provider: row.provider, displayName: row.displayName, placement: row.placement, icon: row.provider.toLowerCase(), startUrl: `/api/v1/auth/social/${row.provider.toLowerCase()}/start` };
    if (row.placement === 'MAIN') grouped.main.push(item);
    if (row.placement === 'MORE') grouped.more.push(item);
  }
  return grouped;
}

export async function getStartRedirect(providerStr: string, req: Request) {
  const provider = normalizeProvider(providerStr);
  const row = await getConfig(provider);
  if (row.status !== SocialIdentityProviderStatus.ACTIVE) throw new AppError('Provider is disabled.', 'PROVIDER_DISABLED', 403);
  if (!row.clientId) throw new AppError('Provider is not configured.', 'PROVIDER_MISCONFIGURED', 400);
  const adapter = getAdapter(provider);
  const nonce = buildStateNonce();
  const codeVerifier = adapter?.requiresPkce ? crypto.randomBytes(32).toString('base64url') : undefined;
  const codeChallenge = codeVerifier ? crypto.createHash('sha256').update(codeVerifier).digest('base64url') : undefined;
  const redirectContext = {
    next: typeof req.query.next === 'string' ? req.query.next : undefined,
    client_id: typeof req.query.client_id === 'string' ? req.query.client_id : undefined,
    redirect_uri: typeof req.query.redirect_uri === 'string' ? req.query.redirect_uri : undefined,
    scope: typeof req.query.scope === 'string' ? req.query.scope : undefined,
    state: typeof req.query.state === 'string' ? req.query.state : undefined,
    response_type: typeof req.query.response_type === 'string' ? req.query.response_type : undefined,
    code_challenge: typeof req.query.code_challenge === 'string' ? req.query.code_challenge : undefined,
    code_challenge_method: typeof req.query.code_challenge_method === 'string' ? req.query.code_challenge_method : undefined,
  };
  const state = jwt.sign({ provider, nonce, redirectContext, codeVerifier }, config.JWT_ACCESS_SECRET, { expiresIn: '10m' });
  if (adapter) {
    const authUrl = adapter.buildAuthorizationUrl(row, state, redirectContext);
    if (codeChallenge) {
      const u = new URL(authUrl);
      u.searchParams.set('code_challenge', codeChallenge);
      u.searchParams.set('code_challenge_method', 'S256');
      return u.toString();
    }
    return authUrl;
  }
  return row.provider === 'APPLE'
    ? `${row.authorizationUrl}?${new URLSearchParams({ response_type: 'code', client_id: row.clientId, redirect_uri: row.redirectUri, scope: row.scopes.join(' '), state, response_mode: 'form_post' }).toString()}`
    : row.provider === 'GITHUB'
      ? `${row.authorizationUrl}?${new URLSearchParams({ response_type: 'code', client_id: row.clientId, redirect_uri: row.redirectUri, scope: row.scopes.join(' '), state, allow_signup: 'true' }).toString()}`
      : `${row.authorizationUrl}?${new URLSearchParams({ response_type: 'code', client_id: row.clientId, redirect_uri: row.redirectUri, scope: row.scopes.join(' '), state }).toString()}`;
}

export async function handleCallback(providerStr: string, code: string, state: string, req: Request): Promise<SocialCallbackResult> {
  const provider = normalizeProvider(providerStr);
  let payload: { provider?: OAuthProvider; codeVerifier?: string; redirectContext?: Record<string, string | undefined> };
  try { payload = jwt.verify(state, config.JWT_ACCESS_SECRET) as { provider?: OAuthProvider; codeVerifier?: string; redirectContext?: Record<string, string | undefined> }; } catch { throw new AppError('Invalid or expired state.', 'INVALID_STATE', 400); }
  if (payload.provider !== provider) throw new AppError('State provider mismatch.', 'INVALID_STATE', 400);
  const row = await getConfig(provider);
  if (row.status !== SocialIdentityProviderStatus.ACTIVE) throw new AppError('Provider is disabled.', 'PROVIDER_DISABLED', 403);
  if (!row.clientId || !row.clientSecretEncrypted) throw new AppError('Provider is not configured.', 'PROVIDER_MISCONFIGURED', 400);
  const secret = decryptSecret(row.clientSecretEncrypted as string).clientSecret;
  if (!secret) throw new AppError('Provider is missing client secret configuration.', 'PROVIDER_MISCONFIGURED', 400);
  const adapter = getAdapter(provider);
  let accessToken = '';
  if (adapter) {
    accessToken = await adapter.exchangeCodeForToken(row, code, { redirectUri: row.redirectUri, clientId: row.clientId!, clientSecret: secret, codeVerifier: payload.codeVerifier });
  } else {
    const tokenParams = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: row.redirectUri, client_id: row.clientId! });
    tokenParams.set('client_secret', secret);
    const tokenRes = await fetch(row.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: tokenParams.toString() });
    const tokenData = (await tokenRes.json()) as { access_token?: string };
    if (!tokenRes.ok) throw new AppError('Token exchange failed.', 'PROVIDER_ERROR', 502);
    accessToken = tokenData.access_token ?? '';
  }
  if (!accessToken) throw new AppError('Token exchange failed.', 'PROVIDER_ERROR', 502);
  const profile = await resolveProfile(provider, accessToken, row);
  return loginOrLink(provider, profile, 'social', req, payload.redirectContext);
}

export async function requestSocialEmailCompletion(completionToken: string, email: string, req: Request) {
  let payload: any;
  try {
    payload = jwt.verify(completionToken, config.JWT_ACCESS_SECRET) as any;
  } catch {
    throw new AppError('Completion token is invalid or has expired.', 'SOCIAL_EMAIL_REQUIRED', 400);
  }
  if (payload.purpose !== 'SOCIAL_EMAIL_COMPLETION') throw new AppError('Completion token is invalid or has expired.', 'SOCIAL_EMAIL_REQUIRED', 400);
  await writeAuditLog({ action: 'SOCIAL_EMAIL_COMPLETION_REQUESTED' as any, metadata: { provider: payload.provider, emailDomain: email.split('@')[1] ?? null }, req });
  return { completionToken: signSocialEmailCompletionToken({ provider: payload.provider, providerUserId: payload.providerUserId, redirectContext: payload.redirectContext, email, code: crypto.randomBytes(3).toString('hex') }) };
}

export async function confirmSocialEmailCompletion(completionToken: string, email: string, code: string, req: Request) {
  let payload: any;
  try {
    payload = jwt.verify(completionToken, config.JWT_ACCESS_SECRET) as any;
  } catch {
    throw new AppError('Completion token is invalid or has expired.', 'SOCIAL_EMAIL_REQUIRED', 400);
  }
  if (payload.purpose !== 'SOCIAL_EMAIL_COMPLETION') throw new AppError('Completion token is invalid or has expired.', 'SOCIAL_EMAIL_REQUIRED', 400);
  if (payload.email !== email || payload.code !== code) throw new AppError('Verification code is invalid.', 'SOCIAL_EMAIL_REQUIRED', 400);
  await writeAuditLog({ action: 'SOCIAL_EMAIL_COMPLETION_CONFIRMED' as any, metadata: { provider: payload.provider, emailDomain: email.split('@')[1] ?? null }, req });
  return { success: true, message: 'Email completion verified.' };
}

export async function upsertProviderConfig(data: {
  provider: OAuthProvider;
  displayName: string;
  clientId?: string | null;
  clientSecret?: string | null;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl?: string | null;
  scopes: string[];
  redirectUri: string;
  status: SocialIdentityProviderStatus;
  environment: SocialIdentityProviderEnvironment;
  placement: SocialIdentityProviderPlacement;
  sortOrder: number;
  showOnLogin: boolean;
  actorId?: string;
}) {
  const { actorId, clientSecret, ...rest } = data;
  const encrypted = data.clientSecret ? JSON.stringify(encryptCredentialPayload({ clientSecret: data.clientSecret })) : undefined;
  return prisma.socialIdentityProviderConfig.upsert({
    where: { provider: data.provider },
    create: { ...rest, clientSecretEncrypted: encrypted, createdByAdminId: actorId, updatedByAdminId: actorId },
    update: { ...rest, clientSecretEncrypted: encrypted ?? undefined, updatedByAdminId: actorId },
  });
}

export async function setProviderStatus(id: string, status: SocialIdentityProviderStatus, actorId?: string) {
  return prisma.socialIdentityProviderConfig.update({ where: { id }, data: { status, updatedByAdminId: actorId } });
}

export async function deleteProvider(id: string) {
  return prisma.socialIdentityProviderConfig.delete({ where: { id } });
}

export async function testProvider(id: string, actorId?: string, req?: Request) {
  const row = await prisma.socialIdentityProviderConfig.findUnique({ where: { id } });
  if (!row) throw new AppError('Provider not found.', 'NOT_FOUND', 404);
  const adapter = getAdapter(row.provider);
  const validations = {
    hasClientId: Boolean(row.clientId),
    hasSecret: Boolean(row.clientSecretEncrypted),
    hasRedirectUri: Boolean(row.redirectUri),
    hasScopes: Array.isArray(row.scopes) && row.scopes.length > 0,
    hasAuthorizationUrl: Boolean(row.authorizationUrl),
    hasTokenUrl: Boolean(row.tokenUrl),
    hasUserInfoUrl: Boolean(row.userInfoUrl),
    hasAdapter: Boolean(adapter || ['GOOGLE', 'FACEBOOK', 'APPLE', 'MICROSOFT'].includes(row.provider)),
  };
  if (!validations.hasClientId || !validations.hasRedirectUri || !validations.hasScopes || !validations.hasAuthorizationUrl || !validations.hasTokenUrl || !validations.hasAdapter) {
    throw new AppError('Provider configuration is incomplete.', 'PROVIDER_MISCONFIGURED', 400);
  }
  if ((row.provider !== 'GOOGLE' && row.provider !== 'FACEBOOK' && row.provider !== 'APPLE' && row.provider !== 'MICROSOFT') && !validations.hasUserInfoUrl) {
    throw new AppError('Provider user info URL is missing.', 'PROVIDER_MISCONFIGURED', 400);
  }
  if (!validations.hasSecret) {
    throw new AppError('Provider secret is not configured.', 'PROVIDER_MISCONFIGURED', 400);
  }
  await writeAuditLog({ userId: actorId, action: 'SOCIAL_PROVIDER_TESTED', resource: 'social_provider', resourceId: id, req, metadata: { provider: row.provider } });
  return { configured: true, status: row.status, provider: row.provider, validations };
}
