import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { OAuthProvider, SocialIdentityProviderEnvironment, SocialIdentityProviderPlacement, SocialIdentityProviderStatus, UserStatus } from '@prisma/client';
import { prisma } from '../../lib/db.js';
import { AppError, ErrorCodes } from '../../lib/errors.js';
import { config } from '../../config/index.js';
import { decryptCredentialPayload, encryptCredentialPayload } from '../../lib/credentialEncryption.js';
import { writeAuditLog } from '../../lib/audit.js';
import { hashToken, parseTtlToSeconds, generateOpaqueToken, signAccessToken, signRefreshToken } from '../../lib/tokens.js';
import { resolveClient, getOrCreateInternalClientId } from './auth.service.js';
import type { Request } from 'express';
import { appCallbackUrl, buildStateNonce, githubAdapter, instagramAdapter, linkedInAdapter, tiktokAdapter, xAdapter, type NormalizedSocialProfile, type SocialProviderAdapter } from './social-providers/index.js';
import { computeProviderReadiness } from './social-readiness.js';
import { getFacebookAuthorizationUrl, getFacebookTokenUrl, getFacebookUserInfoUrl } from './facebookMetaConfig.js';

type ProviderProfile = NormalizedSocialProfile;
type SocialCallbackResult =
  | { kind: 'LOGIN'; accessToken: string; refreshToken: string; expiresIn: number; user: { id: string; email: string | null; displayName: string | null; avatarUrl: string | null; roles: string[] } }
  | { kind: 'EMAIL_REQUIRED'; provider: OAuthProvider; completionToken: string; message: string }
  | { kind: 'LINKED'; provider: OAuthProvider; userId: string }
  | { kind: 'ADMIN_TEST_COMPLETE'; provider: OAuthProvider; redirectUrl: string; lastSuccessfulTestAt: string };

type SocialFlowPurpose = 'SOCIAL_LOGIN' | 'SOCIAL_LINK' | 'ADMIN_PROVIDER_TEST';

type SocialStatePayload = {
  provider?: OAuthProvider;
  purpose?: SocialFlowPurpose;
  nonce?: string;
  redirectContext?: Record<string, string | undefined>;
  codeVerifier?: string;
  clientDbId?: string | null;
  audience?: string | null;
  linkUserId?: string | null;
  adminId?: string | null;
  providerConfigId?: string | null;
  returnTo?: string | null;
  testRunId?: string | null;
};

type AdminProviderTestStart = {
  providerConfigId: string;
  adminId: string;
  returnTo: string;
};

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
  // ENTERPRISE is handled entirely by identity-providers/enterprise.ts (a
  // DB-driven per-org id_token verification path, not this OAuth-code-flow
  // adapter map) — never routed through the legacy /social/:provider/start
  // + callback flow.
  ENTERPRISE: undefined,
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
  ENTERPRISE: { displayName: 'Enterprise SSO', placement: SocialIdentityProviderPlacement.HIDDEN, sortOrder: 10 },
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
    FACEBOOK: { authorizationUrl: getFacebookAuthorizationUrl(), tokenUrl: getFacebookTokenUrl(), userInfoUrl: getFacebookUserInfoUrl(), scopes: ['email', 'public_profile'] },
    APPLE: { authorizationUrl: 'https://appleid.apple.com/auth/authorize', tokenUrl: 'https://appleid.apple.com/auth/token', scopes: ['name', 'email'] },
    MICROSOFT: { authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token', userInfoUrl: 'https://graph.microsoft.com/oidc/userinfo', scopes: ['openid', 'email', 'profile', 'offline_access'] },
    LINKEDIN: { authorizationUrl: 'https://www.linkedin.com/oauth/v2/authorization', tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken', userInfoUrl: 'https://api.linkedin.com/v2/userinfo', scopes: ['openid', 'profile', 'email'] },
    TIKTOK: { authorizationUrl: 'https://www.tiktok.com/v2/auth/authorize/', tokenUrl: 'https://open.tiktokapis.com/v2/oauth/token/', userInfoUrl: 'https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name', scopes: ['user.info.basic'] },
    X: { authorizationUrl: 'https://twitter.com/i/oauth2/authorize', tokenUrl: 'https://api.x.com/2/oauth2/token', userInfoUrl: 'https://api.x.com/2/users/me?user.fields=profile_image_url', scopes: ['tweet.read', 'users.read', 'offline.access'] },
    GITHUB: { authorizationUrl: 'https://github.com/login/oauth/authorize', tokenUrl: 'https://github.com/login/oauth/access_token', userInfoUrl: 'https://api.github.com/user', scopes: ['read:user', 'user:email'] },
    INSTAGRAM: {
      authorizationUrl: 'https://api.instagram.com/oauth/authorize',
      tokenUrl: 'https://api.instagram.com/oauth/access_token',
      userInfoUrl: 'https://graph.instagram.com/v26.0/me?fields=id,username',
      scopes: ['instagram_business_basic'],
    },
    // Never actually used by this legacy OAuth-code-flow map (see
    // adapterMap above) — present only so this lookup object stays a total
    // function over OAuthProvider.
    ENTERPRISE: { authorizationUrl: '', tokenUrl: '', scopes: [] },
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

function buildAdminTestResultUrl(returnTo: string, result: 'success' | 'failure', provider: OAuthProvider, message?: string) {
  const url = new URL(returnTo);
  url.searchParams.set('provider', provider);
  url.searchParams.set('test', result);
  if (message) url.searchParams.set('message', message);
  return url.toString();
}

function signSocialState(payload: SocialStatePayload) {
  return jwt.sign(payload, config.JWT_ACCESS_SECRET, { expiresIn: '10m' });
}

export function verifySocialState(state: string): SocialStatePayload {
  try {
    return jwt.verify(state, config.JWT_ACCESS_SECRET) as SocialStatePayload;
  } catch {
    throw new AppError('Invalid or expired state.', 'INVALID_STATE', 400);
  }
}

async function recordProviderTestOutcome(input: {
  rowId: string;
  success: boolean;
  errorMessage?: string | null;
  req?: Request;
  actorId?: string | null;
}) {
  const now = new Date();
  const data = input.success
    ? {
        lastTestAt: now,
        lastSuccessfulTestAt: now,
        lastTestStatus: 'SUCCESS',
        lastTestError: null,
      }
    : {
        lastTestAt: now,
        lastTestStatus: 'FAILED',
        lastTestError: (input.errorMessage ?? 'Provider test failed.').slice(0, 500),
      };

  await prisma.socialIdentityProviderConfig.update({
    where: { id: input.rowId },
    data,
  });

  try {
    await writeAuditLog({
      userId: input.actorId ?? undefined,
      action: 'SOCIAL_PROVIDER_TESTED',
      resource: 'social_provider',
      resourceId: input.rowId,
      req: input.req,
      metadata: { success: input.success },
    });
  } catch (err) {
    console.error('Failed to write social provider test audit log:', err);
  }

  return now;
}

export async function recordProviderTestFailure(input: {
  rowId: string;
  errorMessage?: string | null;
  req?: Request;
  actorId?: string | null;
}) {
  return recordProviderTestOutcome({
    rowId: input.rowId,
    success: false,
    errorMessage: input.errorMessage,
    req: input.req,
    actorId: input.actorId,
  });
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

// Explicit account linking: attach a social identity to an already
// logged-in user. Never merges silently — an identity already linked to a
// DIFFERENT user throws IDENTITY_ALREADY_LINKED rather than moving it.
async function linkIdentityToUser(provider: OAuthProvider, profile: ProviderProfile, userId: string, req: Request): Promise<SocialCallbackResult> {
  if (!profile.providerUserId) throw new AppError('Provider returned an invalid profile.', ErrorCodes.INVALID_PROVIDER_TOKEN, 502);
  const existingAccount = await prisma.oAuthAccount.findUnique({ where: { provider_providerAccountId: { provider, providerAccountId: profile.providerUserId } } });
  if (existingAccount) {
    if (existingAccount.userId !== userId) {
      throw new AppError('This account is already linked to a different user.', ErrorCodes.IDENTITY_ALREADY_LINKED, 409);
    }
    await prisma.oAuthAccount.update({
      where: { id: existingAccount.id },
      data: { lastLoginAt: new Date(), rawProfile: sanitizeProfile(profile) },
    });
    return { kind: 'LINKED', provider, userId };
  }
  try {
    await prisma.oAuthAccount.create({
      data: {
        userId,
        provider,
        providerAccountId: profile.providerUserId,
        rawProfile: sanitizeProfile(profile),
        email: profile.email ?? null,
        emailVerifiedAt: profile.emailVerified ? new Date() : null,
        lastLoginAt: new Date(),
      },
    });
  } catch (err: any) {
    // Unique constraint race: the identity got linked to someone else
    // between the findUnique above and this create.
    if (err?.code === 'P2002') {
      throw new AppError('This account is already linked to a different user.', ErrorCodes.IDENTITY_ALREADY_LINKED, 409);
    }
    throw err;
  }
  await writeAuditLog({ userId, action: 'OAUTH_LINKED', metadata: { provider }, req });
  return { kind: 'LINKED', provider, userId };
}

async function loginOrLink(
  provider: OAuthProvider,
  profile: ProviderProfile,
  clientId: string,
  req: Request,
  redirectContext?: Record<string, string | undefined>,
  audience?: string,
): Promise<SocialCallbackResult> {
  if (!profile.providerUserId) throw new AppError('Provider returned an invalid profile.', ErrorCodes.INVALID_PROVIDER_TOKEN, 502);
  const existingAccount = await prisma.oAuthAccount.findUnique({ where: { provider_providerAccountId: { provider, providerAccountId: profile.providerUserId } }, include: { user: true } });
  let user = existingAccount?.user;

  if (!user && profile.email && profile.emailVerified) {
    const emailMatch = await prisma.user.findFirst({ where: { email: profile.email, emailVerifiedAt: { not: null } } });
    if (emailMatch) {
      // Never merge if that account already has a DIFFERENT identity for
      // this same provider linked (would silently orphan the old one) —
      // surface as a typed conflict instead of guessing which is correct.
      const conflictingAccount = await prisma.oAuthAccount.findFirst({
        where: { userId: emailMatch.id, provider, NOT: { providerAccountId: profile.providerUserId } },
      });
      if (conflictingAccount) {
        throw new AppError(
          'This email is already associated with a different social account for this provider.',
          ErrorCodes.ACCOUNT_CONFLICT,
          409,
        );
      }
      user = emailMatch;
    }
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
    try {
      await prisma.oAuthAccount.create({
        data: {
          userId: user.id,
          provider,
          providerAccountId: profile.providerUserId,
          rawProfile: sanitizeProfile(profile),
          email: profile.email ?? null,
          emailVerifiedAt: profile.emailVerified ? new Date() : null,
          lastLoginAt: new Date(),
        },
      });
    } catch (err: any) {
      if (err?.code === 'P2002') {
        throw new AppError('This social identity is already linked to a different user.', ErrorCodes.IDENTITY_ALREADY_LINKED, 409);
      }
      throw err;
    }
  } else {
    await prisma.oAuthAccount.update({
      where: { id: existingAccount.id },
      data: { lastLoginAt: new Date(), rawProfile: sanitizeProfile(profile) },
    });
  }
  const rolesRows = await prisma.userRole.findMany({ where: { userId: user.id }, include: { role: true } });
  const roles = rolesRows.map((r) => r.role.name);
  const refreshToken = signRefreshToken(user.id, audience);
  const session = await prisma.loginSession.create({
    data: {
      userId: user.id,
      clientId,
      sessionToken: generateOpaqueToken(),
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
    },
  });
  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email,
    username: user.username,
    roles,
    sid: session.id,
  }, audience);
  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId,
      tokenHash: hashToken(refreshToken),
      scopes: ['openid', 'offline_access'],
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
      familyId: session.id,
    },
  });
  await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  await writeAuditLog({ userId: user.id, clientId, action: 'LOGIN', metadata: { method: 'social', provider }, req });
  return { kind: 'LOGIN', accessToken, refreshToken, expiresIn: parseTtlToSeconds(config.ACCESS_TOKEN_TTL), user: { id: user.id, email: user.email, displayName: user.displayName, avatarUrl: user.avatarUrl, roles } };
}

export async function listPublicProviders() {
  const rows = await prisma.socialIdentityProviderConfig.findMany({ where: { status: SocialIdentityProviderStatus.ACTIVE, showOnLogin: true }, orderBy: [{ placement: 'asc' }, { sortOrder: 'asc' }, { displayName: 'asc' }] });
  const grouped = { main: [] as Array<Record<string, unknown>>, more: [] as Array<Record<string, unknown>> };
  for (const row of rows) {
    const readiness = computeProviderReadiness(row as any);
    if (!readiness.visibleOnLogin) continue;
    const item = { id: row.id, provider: row.provider, displayName: row.displayName, placement: row.placement, icon: row.provider.toLowerCase(), startUrl: `/api/v1/auth/social/${row.provider.toLowerCase()}/start`, readiness };
    if (row.placement === 'MAIN') grouped.main.push(item);
    if (row.placement === 'MORE') grouped.more.push(item);
  }
  return grouped;
}

/**
 * Resolves the mobile-app custom-scheme redirect target for a social
 * callback, if — and only if — the signed `state` carries a
 * `redirectContext.redirect_uri` that is (a) a non-http custom scheme and
 * (b) registered in the requesting AuthClient's `redirectUris` allow-list
 * (e.g. `furtailapp://oauth-callback`). Returns null in every other case,
 * in which the callback keeps its existing JSON response behavior (used by
 * BPA and web callers) unchanged. Never throws.
 */
export type MobileRedirectContext = {
  redirectUri: string;
  clientDbId: string;
  /// S256 code challenge the app supplied on /start — required to hand back
  /// an authorization code; a mobile redirect without one gets a typed
  /// PKCE_REQUIRED error instead of any credential material.
  codeChallenge: string | null;
  /// The app's own opaque state value (echoed back so it can bind the
  /// callback to the flow it started). Distinct from the server's signed
  /// state JWT.
  appState: string | null;
};

export async function resolveMobileRedirect(state: string): Promise<MobileRedirectContext | null> {
  try {
    const payload = jwt.verify(state, config.JWT_ACCESS_SECRET) as {
      redirectContext?: Record<string, string | undefined>;
      clientDbId?: string | null;
    };
    const target = payload.redirectContext?.redirect_uri;
    if (!target || !payload.clientDbId) return null;
    const scheme = target.split(':')[0]?.toLowerCase();
    if (!scheme || scheme === 'http' || scheme === 'https') return null;
    const client = await prisma.authClient.findUnique({ where: { id: payload.clientDbId } });
    if (!client || client.status !== 'ACTIVE') return null;
    if (!client.redirectUris.includes(target)) return null;
    return {
      redirectUri: target,
      clientDbId: client.id,
      codeChallenge: payload.redirectContext?.code_challenge || null,
      appState: payload.redirectContext?.state || null,
    };
  } catch {
    return null;
  }
}

export async function getStartRedirect(providerStr: string, req: Request, opts?: { linkUserId?: string; adminTest?: AdminProviderTestStart }) {
  const provider = normalizeProvider(providerStr);
  const row = await getConfig(provider);
  const readiness = computeProviderReadiness(row as any);
  const isAdminTest = Boolean(opts?.adminTest);
  if (!isAdminTest && row.status !== SocialIdentityProviderStatus.ACTIVE && !opts?.linkUserId) throw new AppError('Provider is disabled.', ErrorCodes.PROVIDER_DISABLED, 403);
  if (!isAdminTest && !opts?.linkUserId && row.status === SocialIdentityProviderStatus.ACTIVE && !readiness.readyForProduction) throw new AppError(`Provider is not ready for production login: ${readiness.blockers.join(' | ')}`, 'PROVIDER_MISCONFIGURED', 400);
  if (isAdminTest && !readiness.canTest) {
    throw new AppError(`${row.displayName} cannot be tested yet.`, 'PROVIDER_TEST_NOT_READY', 400, {
      blockers: readiness.testBlockers,
      lifecycleStage: readiness.lifecycleStage,
    });
  }
  if (!row.clientId) throw new AppError('Provider is not configured.', 'PROVIDER_MISCONFIGURED', 400);
  const adapter = getAdapter(provider);
  const nonce = buildStateNonce();
  const codeVerifier = adapter?.requiresPkce ? crypto.randomBytes(32).toString('base64url') : undefined;
  const codeChallenge = codeVerifier ? crypto.createHash('sha256').update(codeVerifier).digest('base64url') : undefined;
  const query = req?.query ?? {};
  const redirectContext = {
    next: typeof query.next === 'string' ? query.next : undefined,
    client_id: typeof query.client_id === 'string' ? query.client_id : undefined,
    redirect_uri: typeof query.redirect_uri === 'string' ? query.redirect_uri : undefined,
    scope: typeof query.scope === 'string' ? query.scope : undefined,
    state: typeof query.state === 'string' ? query.state : undefined,
    response_type: typeof query.response_type === 'string' ? query.response_type : undefined,
    code_challenge: typeof query.code_challenge === 'string' ? query.code_challenge : undefined,
    code_challenge_method: typeof query.code_challenge_method === 'string' ? query.code_challenge_method : undefined,
  };
  // App-aware client attribution (Furtail centralized-auth onboarding):
  // `app_client_id` is this app's own AuthClient.clientId (e.g.
  // "furtail-mobile"), distinct from the OAuth-relying-party `client_id`
  // passthrough already used above for the /oauth/authorize bridge. When
  // omitted (e.g. existing BPA calls), clientDbId/audience stay null and
  // handleCallback falls back to the internal default client — the same
  // effective behavior as before, minus the previous hardcoded-'social'
  // foreign-key bug.
  const appClientIdParam = typeof query.app_client_id === 'string' ? query.app_client_id : undefined;
  const requestingClient = appClientIdParam ? await resolveClient(appClientIdParam, req) : null;
  const state = signSocialState({
    provider,
    purpose: isAdminTest ? 'ADMIN_PROVIDER_TEST' : opts?.linkUserId ? 'SOCIAL_LINK' : 'SOCIAL_LOGIN',
    nonce,
    redirectContext,
    codeVerifier,
    clientDbId: requestingClient?.id ?? null,
    audience: requestingClient?.audience ?? null,
    linkUserId: opts?.linkUserId ?? null,
    adminId: opts?.adminTest?.adminId ?? null,
    providerConfigId: opts?.adminTest?.providerConfigId ?? null,
    returnTo: opts?.adminTest?.returnTo ?? null,
    testRunId: isAdminTest ? crypto.randomUUID() : null,
  });
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

export async function getAdminTestStartRedirect(input: AdminProviderTestStart, req: Request): Promise<string> {
  const row = await prisma.socialIdentityProviderConfig.findUnique({ where: { id: input.providerConfigId } });
  if (!row) throw new AppError('Provider not found.', 'NOT_FOUND', 404);
  return getStartRedirect(row.provider, req, { adminTest: input });
}

export async function handleCallback(providerStr: string, code: string, state: string, req: Request): Promise<SocialCallbackResult> {
  const provider = normalizeProvider(providerStr);
  const payload = verifySocialState(state);
  if (payload.provider !== provider) throw new AppError('State provider mismatch.', 'INVALID_STATE', 400);
  const row = await getConfig(provider);
  const readiness = computeProviderReadiness(row as any);
  const isAdminTest = payload.purpose === 'ADMIN_PROVIDER_TEST';
  if (!isAdminTest && row.status !== SocialIdentityProviderStatus.ACTIVE) throw new AppError('Provider is disabled.', ErrorCodes.PROVIDER_DISABLED, 403);
  if (!isAdminTest && !readiness.readyForProduction) throw new AppError(`Provider is not ready for production login: ${readiness.blockers.join(' | ')}`, 'PROVIDER_MISCONFIGURED', 400);
  if (isAdminTest && !readiness.canTest) {
    throw new AppError(`${row.displayName} cannot be tested yet.`, 'PROVIDER_TEST_NOT_READY', 400, {
      blockers: readiness.testBlockers,
      lifecycleStage: readiness.lifecycleStage,
    });
  }
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
    if (!tokenRes.ok) throw new AppError('Token exchange failed.', ErrorCodes.INVALID_PROVIDER_TOKEN, 502);
    accessToken = tokenData.access_token ?? '';
  }
  if (!accessToken) throw new AppError('Token exchange failed.', ErrorCodes.INVALID_PROVIDER_TOKEN, 502);
  const profile = await resolveProfile(provider, accessToken, row);

  if (isAdminTest) {
    if (!payload.providerConfigId || payload.providerConfigId !== row.id) {
      throw new AppError('Provider test state did not match the configured provider.', 'INVALID_STATE', 400);
    }
    const redirectTo = buildAdminTestResultUrl(
      payload.returnTo ?? `${config.ADMIN_PANEL_ORIGIN.replace(/\/$/, '')}/authentication/social-providers`,
      'success',
      provider,
    );
    const lastSuccessfulTestAt = await recordProviderTestOutcome({
      rowId: row.id,
      success: true,
      req,
      actorId: payload.adminId ?? undefined,
    });
    return {
      kind: 'ADMIN_TEST_COMPLETE',
      provider,
      redirectUrl: redirectTo,
      lastSuccessfulTestAt: lastSuccessfulTestAt.toISOString(),
    };
  }

  if (payload.linkUserId) {
    return linkIdentityToUser(provider, profile, payload.linkUserId, req);
  }

  // Fixes the previous hardcoded `clientId: 'social'` bug: that string was
  // not a real AuthClient.id, so every social-login LoginSession/RefreshToken
  // row violated the clientId foreign key. Now we use the real requesting
  // AuthClient (threaded through /start via app_client_id) or fall back to
  // the internal default client — the same fallback already used by
  // password login when no clientId is supplied.
  const clientId = payload.clientDbId ?? (await getOrCreateInternalClientId());
  return loginOrLink(provider, profile, clientId, req, payload.redirectContext, payload.audience ?? undefined);
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
  const readiness = computeProviderReadiness(row as any);
  if (!readiness.canTest) {
    throw new AppError(`${row.displayName} cannot be tested yet.`, 'PROVIDER_TEST_NOT_READY', 400, {
      blockers: readiness.testBlockers,
      lifecycleStage: readiness.lifecycleStage,
    });
  }
  const returnTo = `${config.ADMIN_PANEL_ORIGIN.replace(/\/$/, '')}/authentication/social-providers`;
  const testUrl = await getAdminTestStartRedirect({
    providerConfigId: row.id,
    adminId: actorId ?? '',
    returnTo,
  }, req as Request);
  return { success: true, provider: row.provider, readiness, testUrl };
}
