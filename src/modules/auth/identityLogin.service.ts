// Central login/linking logic shared by every OIDC/token-verified identity
// provider (Google, Facebook, Apple, Microsoft, per-org Enterprise OIDC) —
// one normalized code path so the account-linking invariants proven in
// identityFoundation.integration.test.ts (unique provider+providerAccountId,
// no cross-user identity stealing, no merge-by-unverified-email) apply
// identically no matter which provider produced the profile. Deliberately
// mirrors loginOrLink()/linkIdentityToUser() in social.service.ts (the
// existing OAuth-code-flow providers) rather than inventing new semantics.
import bcrypt from 'bcrypt';
import type { Request } from 'express';
import { OAuthProvider, UserStatus } from '@prisma/client';
import { prisma } from '../../lib/db.js';
import { config } from '../../config/index.js';
import { AppError, ErrorCodes } from '../../lib/errors.js';
import { writeAuditLog } from '../../lib/audit.js';
import {
  signAccessToken,
  signRefreshToken,
  hashToken,
  generateOpaqueToken,
  parseTtlToSeconds,
} from '../../lib/tokens.js';
import { getClientIp } from '../../lib/antiAbuse.js';
import { resolveClient, getOrCreateInternalClientId } from './auth.service.js';
import type { NormalizedIdentityProfile } from './identity-providers/types.js';
import { getAccountAuthenticationState } from './accountPolicy.js';

const BCRYPT_ROUNDS = 12;

export type IdentityLoginResult =
  | {
      kind: 'LOGIN';
      accessToken: string;
      refreshToken: string;
      expiresIn: number;
      user: { id: string; email: string | null; displayName: string | null; avatarUrl: string | null; roles: string[] };
    }
  | {
      kind: 'NEEDS_PROFILE_COMPLETION';
      provider: OAuthProvider;
      userId: string;
      missingFields: string[];
      message: string;
    };

function missingRequiredFields(user: { phone: string | null; displayName: string | null; email: string | null }, required: string[]): string[] {
  const missing: string[] = [];
  for (const field of required) {
    if (field === 'phone' && !user.phone) missing.push('phone');
    if (field === 'displayName' && !user.displayName) missing.push('displayName');
    if (field === 'email' && !user.email) missing.push('email');
  }
  return missing;
}

async function issueSession(userId: string, clientDbId: string, audience: string | undefined, req: Request) {
  const roles = (await prisma.userRole.findMany({ where: { userId }, include: { role: true } })).map((r) => r.role.name);
  const session = await prisma.loginSession.create({
    data: {
      userId,
      clientId: clientDbId,
      sessionToken: generateOpaqueToken(),
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
    },
  });
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
  const accessToken = signAccessToken({ sub: userId, email: user.email, username: user.username, name: user.displayName, roles, sid: session.id }, audience);
  const refreshToken = signRefreshToken(userId, audience);
  await prisma.refreshToken.create({
    data: {
      userId,
      clientId: clientDbId,
      tokenHash: hashToken(refreshToken),
      scopes: ['openid', 'offline_access'],
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      familyId: session.id,
    },
  });
  await prisma.user.update({ where: { id: userId }, data: { lastLoginAt: new Date() } });
  return { accessToken, refreshToken, expiresIn: parseTtlToSeconds(config.ACCESS_TOKEN_TTL), roles, user };
}

/**
 * Login (or first-time account creation / auto-link) via a verified,
 * token-based identity provider profile. NEVER merges on an unverified
 * email — only a provider-asserted-verified email matching an existing
 * user's own verified email triggers auto-link; otherwise a brand-new user
 * is created. Two different users can never end up sharing one
 * (provider, providerAccountId) row — enforced at the DB level
 * (OAuthAccount unique constraint), surfaced here as IDENTITY_ALREADY_LINKED
 * or a P2002-driven equivalent.
 */
export async function oidcLoginOrCreate(
  profile: NormalizedIdentityProfile,
  clientIdParam: string | undefined,
  req: Request,
): Promise<IdentityLoginResult> {
  if (!profile.providerUserId) {
    throw new AppError('Provider returned an invalid profile.', ErrorCodes.INVALID_PROVIDER_TOKEN, 502);
  }

  const client = await resolveClient(clientIdParam, req);
  const clientDbId = client?.id ?? (await getOrCreateInternalClientId());
  const audience = client?.audience ?? undefined;
  const requiredFields = client?.requiredProfileFields ?? [];

  const existingAccount = await prisma.oAuthAccount.findUnique({
    where: { provider_providerAccountId: { provider: profile.provider, providerAccountId: profile.providerUserId } },
    include: { user: true },
  });
  let user = existingAccount?.user;

  if (!user && profile.email && profile.emailVerified) {
    const emailMatch = await prisma.user.findFirst({ where: { email: profile.email, emailVerifiedAt: { not: null } } });
    if (emailMatch) {
      const conflicting = await prisma.oAuthAccount.findFirst({
        where: { userId: emailMatch.id, provider: profile.provider, NOT: { providerAccountId: profile.providerUserId } },
      });
      if (conflicting) {
        throw new AppError(
          'This email is already associated with a different account for this provider.',
          ErrorCodes.ACCOUNT_CONFLICT,
          409,
        );
      }
      user = emailMatch;
    }
  }

  if (!user) {
    if (client && !client.registrationOpen) {
      throw new AppError('Registration is closed for this application.', 'REGISTRATION_CLOSED', 403);
    }
    user = await prisma.user.create({
      data: {
        email: profile.email,
        displayName: profile.displayName,
        avatarUrl: profile.avatarUrl,
        emailVerifiedAt: profile.emailVerified ? new Date() : null,
        status: UserStatus.ACTIVE,
        registrationSource: `identity:${profile.provider.toLowerCase()}`,
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
          provider: profile.provider,
          providerAccountId: profile.providerUserId,
          rawProfile: { providerUserId: profile.providerUserId, hasEmail: Boolean(profile.email) },
          email: profile.email ?? null,
          emailVerifiedAt: profile.emailVerified ? new Date() : null,
          lastLoginAt: new Date(),
        },
      });
    } catch (err: any) {
      if (err?.code === 'P2002') {
        throw new AppError('This identity is already linked to a different user.', ErrorCodes.IDENTITY_ALREADY_LINKED, 409);
      }
      throw err;
    }
  } else {
    await prisma.oAuthAccount.update({ where: { id: existingAccount.id }, data: { lastLoginAt: new Date() } });
  }

  const missing = missingRequiredFields(user, requiredFields);
  if (missing.length > 0) {
    await writeAuditLog({ userId: user.id, clientId: clientDbId, action: 'LOGIN', metadata: { method: 'identity', provider: profile.provider, needsProfileCompletion: true }, req });
    return {
      kind: 'NEEDS_PROFILE_COMPLETION',
      provider: profile.provider,
      userId: user.id,
      missingFields: missing,
      message: `Please complete your profile (${missing.join(', ')}) to continue.`,
    };
  }

  const { accessToken, refreshToken, expiresIn, roles } = await issueSession(user.id, clientDbId, audience, req);
  await writeAuditLog({ userId: user.id, clientId: clientDbId, action: 'LOGIN', metadata: { method: 'identity', provider: profile.provider }, req });

  return {
    kind: 'LOGIN',
    accessToken,
    refreshToken,
    expiresIn,
    user: { id: user.id, email: user.email, displayName: user.displayName, avatarUrl: user.avatarUrl, roles },
  };
}

/** Explicit account-linking for an already-authenticated user (not at login time). */
export async function linkIdentityToExistingUser(profile: NormalizedIdentityProfile, userId: string, req: Request) {
  if (!profile.providerUserId) throw new AppError('Provider returned an invalid profile.', ErrorCodes.INVALID_PROVIDER_TOKEN, 502);
  const existing = await prisma.oAuthAccount.findUnique({
    where: { provider_providerAccountId: { provider: profile.provider, providerAccountId: profile.providerUserId } },
  });
  if (existing) {
    if (existing.userId !== userId) {
      throw new AppError('This identity is already linked to a different user.', ErrorCodes.IDENTITY_ALREADY_LINKED, 409);
    }
    await prisma.oAuthAccount.update({ where: { id: existing.id }, data: { lastLoginAt: new Date() } });
    return { linked: true, provider: profile.provider };
  }
  try {
    await prisma.oAuthAccount.create({
      data: {
        userId,
        provider: profile.provider,
        providerAccountId: profile.providerUserId,
        rawProfile: { providerUserId: profile.providerUserId, hasEmail: Boolean(profile.email) },
        email: profile.email ?? null,
        emailVerifiedAt: profile.emailVerified ? new Date() : null,
        lastLoginAt: new Date(),
      },
    });
  } catch (err: any) {
    if (err?.code === 'P2002') {
      throw new AppError('This identity is already linked to a different user.', ErrorCodes.IDENTITY_ALREADY_LINKED, 409);
    }
    throw err;
  }
  await writeAuditLog({ userId, action: 'OAUTH_LINKED', metadata: { provider: profile.provider }, req });
  return { linked: true, provider: profile.provider };
}

// ─── Linked-identity management (read + unlink) ──────────────────────────────

export type LinkedIdentity = {
  id: string;
  provider: OAuthProvider;
  email: string | null;
  emailVerified: boolean;
  linkedAt: Date;
  lastLoginAt: Date | null;
};

/**
 * Read-only list of external identities linked to a Central Auth user.
 * Never returns provider access/refresh tokens or raw profile blobs — only
 * the safe, display-oriented fields the account/linking screen needs.
 */
export async function listLinkedIdentities(userId: string): Promise<LinkedIdentity[]> {
  const rows = await prisma.oAuthAccount.findMany({
    where: { userId },
    select: {
      id: true,
      provider: true,
      email: true,
      emailVerifiedAt: true,
      createdAt: true,
      lastLoginAt: true,
    },
    orderBy: { createdAt: 'asc' },
  });
  return rows.map((r) => ({
    id: r.id,
    provider: r.provider,
    email: r.email,
    emailVerified: Boolean(r.emailVerifiedAt),
    linkedAt: r.createdAt,
    lastLoginAt: r.lastLoginAt,
  }));
}

/**
 * Unlinks an external identity from the current user. Safety invariant: never
 * leave an account with no way to sign in. Unlinking is refused (409) when it
 * would remove the user's last remaining login method (i.e. no password set
 * and this is the only linked identity).
 */
export async function unlinkIdentity(userId: string, provider: OAuthProvider, req: Request) {
  const account = await prisma.oAuthAccount.findFirst({ where: { userId, provider } });
  if (!account) {
    throw new AppError('No linked identity for that provider.', 'NOT_FOUND', 404);
  }
  const [identityCount, user] = await Promise.all([
    prisma.oAuthAccount.count({ where: { userId } }),
    prisma.user.findUnique({ where: { id: userId }, select: { passwordHash: true } }),
  ]);
  const hasPassword = Boolean(user?.passwordHash);
  if (!hasPassword && identityCount <= 1) {
    throw new AppError(
      'Cannot unlink your only login method. Set a password first.',
      'LAST_LOGIN_METHOD',
      409,
    );
  }
  await prisma.oAuthAccount.delete({ where: { id: account.id } });
  await writeAuditLog({ userId, action: 'OAUTH_UNLINKED', metadata: { provider }, req });
  return { unlinked: true, provider };
}

// ─── Phone + password login ─────────────────────────────────────────────────
// Only usable for accounts with a VERIFIED phone AND a password set —
// distinct from the general email/username/phone loginUser() in
// auth.service.ts (which doesn't require phone verification and predates
// this stricter rule). Issues tokens via the exact same session/refresh
// machinery as every other login path.
export async function loginWithPhonePassword(opts: { phone: string; password: string; clientId?: string }, req: Request) {
  const phone = opts.phone.trim();
  const user = await prisma.user.findFirst({ where: { phone } });
  if (!user || !user.passwordHash || !user.phoneVerifiedAt) {
    throw new AppError('Invalid credentials.', 'INVALID_CREDENTIALS', 401);
  }
  const valid = await bcrypt.compare(opts.password, user.passwordHash);
  if (!valid) {
    throw new AppError('Invalid credentials.', 'INVALID_CREDENTIALS', 401);
  }
  const accountState = getAccountAuthenticationState(user.status);
  if (accountState === 'suspended') throw new AppError('Your account has been suspended.', 'ACCOUNT_SUSPENDED', 403);
  if (accountState === 'deleted') throw new AppError('Invalid credentials.', 'INVALID_CREDENTIALS', 401);

  const client = await resolveClient(opts.clientId, req);
  const clientDbId = client?.id ?? (await getOrCreateInternalClientId());
  const audience = client?.audience ?? undefined;
  const { accessToken, refreshToken, expiresIn, roles } = await issueSession(user.id, clientDbId, audience, req);
  await writeAuditLog({ userId: user.id, clientId: clientDbId, action: 'LOGIN', metadata: { method: 'phone_password' }, req });
  return { accessToken, refreshToken, expiresIn, user: { id: user.id, email: user.email, phone: user.phone, displayName: user.displayName, roles } };
}

// ─── Set password for a social/OIDC-only account ────────────────────────────
export async function setPasswordForCurrentUser(userId: string, newPassword: string, req: Request) {
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { passwordHash: true } });
  if (!user) throw new AppError('User not found.', 'NOT_FOUND', 404);
  if (user.passwordHash) {
    throw new AppError('A password is already set on this account. Use "Change Password" instead.', 'PASSWORD_ALREADY_SET', 409);
  }
  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await prisma.user.update({ where: { id: userId }, data: { passwordHash, lastPasswordChangedAt: new Date() } });
  await writeAuditLog({ userId, action: 'PASSWORD_CHANGED', resource: 'user', resourceId: userId, req, metadata: { firstTimeSet: true } });
  return { success: true };
}
