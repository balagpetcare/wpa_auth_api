import { Prisma, type OAuthAccount } from '@prisma/client';
import type { Request } from 'express';
import { prisma } from '../../lib/db.js';
import { AppError } from '../../lib/errors.js';
import { config } from '../../config/index.js';
import { verifyMetaSignedRequest, type MetaSignedRequestPayload } from '../../lib/metaSignedRequest.js';
import { writeAuditLog, writeSecurityEvent } from '../../lib/audit.js';
import { resolveFacebookAppCredentials } from './facebookMetaConfig.js';

type AccountRecord = Pick<OAuthAccount, 'id' | 'userId' | 'rawProfile'>;

type DeauthorizeDeps = {
  verifySignedRequest: (signedRequest: string) => Promise<MetaSignedRequestPayload> | MetaSignedRequestPayload;
  findFacebookAccountByProviderUserId: (providerUserId: string) => Promise<AccountRecord | null>;
  getUserLoginState: (userId: string) => Promise<{ hasPassword: boolean; identityCount: number }>;
  unlinkOAuthAccount: (id: string) => Promise<void>;
  markOAuthAccountDeauthorized: (id: string, metadata: Record<string, unknown>) => Promise<void>;
  writeAuditUnlinked: (userId: string, providerUserId: string, req?: Request) => Promise<void>;
  writeSecurityEvent: (userId: string | undefined, metadata: Record<string, unknown>, req?: Request) => Promise<void>;
};

function defaultDeps(): DeauthorizeDeps {
  return {
    verifySignedRequest: async (signedRequest) => {
      const credentials = await resolveFacebookAppCredentials();
      return verifyMetaSignedRequest(signedRequest, credentials?.appSecret ?? config.FACEBOOK_APP_SECRET ?? '');
    },
    findFacebookAccountByProviderUserId: (providerUserId) =>
      prisma.oAuthAccount.findUnique({
        where: { provider_providerAccountId: { provider: 'FACEBOOK', providerAccountId: providerUserId } },
        select: { id: true, userId: true, rawProfile: true },
      }),
    getUserLoginState: async (userId) => {
      const [identityCount, user] = await Promise.all([
        prisma.oAuthAccount.count({ where: { userId } }),
        prisma.user.findUnique({ where: { id: userId }, select: { passwordHash: true } }),
      ]);
      return { hasPassword: Boolean(user?.passwordHash), identityCount };
    },
    unlinkOAuthAccount: (id) => prisma.oAuthAccount.delete({ where: { id } }).then(() => undefined),
    markOAuthAccountDeauthorized: async (id, metadata) => {
      const existing = await prisma.oAuthAccount.findUnique({ where: { id }, select: { rawProfile: true } });
      const current = existing?.rawProfile && typeof existing.rawProfile === 'object' ? existing.rawProfile as Record<string, unknown> : {};
      await prisma.oAuthAccount.update({
        where: { id },
        data: {
          accessToken: null,
          refreshToken: null,
          tokenExpiresAt: null,
          rawProfile: {
            ...(current as Prisma.JsonObject),
            metaDeauthorizedAt: new Date().toISOString(),
            metaDeauthorizeSource: 'meta_callback',
            metaDeauthorizeMetadata: metadata as Prisma.JsonObject,
          },
        },
      });
    },
    writeAuditUnlinked: (userId, providerUserId, req) =>
      writeAuditLog({
        userId,
        action: 'OAUTH_UNLINKED',
        resource: 'oauth_account',
        metadata: { provider: 'FACEBOOK', providerUserId, source: 'META_DEAUTHORIZE_CALLBACK', strategy: 'unlink' },
        req,
      }),
    writeSecurityEvent: (userId, metadata, req) =>
      writeSecurityEvent({
        userId,
        type: 'SUSPICIOUS_OAUTH',
        severity: 'LOW',
        metadata: metadata as Prisma.InputJsonValue,
        req,
      }),
  };
}

export type FacebookDeauthorizeResult =
  | { handled: true; action: 'already_absent'; providerUserId: string }
  | { handled: true; action: 'unlinked'; providerUserId: string; userId: string }
  | { handled: true; action: 'marked_deauthorized'; providerUserId: string; userId: string };

export async function handleFacebookDeauthorizeCallback(
  input: { signedRequest: string; req?: Request },
  deps: DeauthorizeDeps = defaultDeps(),
): Promise<FacebookDeauthorizeResult> {
  const payload = await deps.verifySignedRequest(input.signedRequest);
  const providerUserId = typeof payload.user_id === 'string' && payload.user_id.trim() ? payload.user_id : null;
  if (!providerUserId) {
    throw new AppError('Meta signed request is missing user_id.', 'VALIDATION_ERROR', 400);
  }

  const account = await deps.findFacebookAccountByProviderUserId(providerUserId);
  if (!account) {
    await deps.writeSecurityEvent(undefined, {
      event: 'META_DEAUTHORIZE_CALLBACK',
      provider: 'FACEBOOK',
      providerUserIdKnown: false,
      strategy: 'already_absent',
    }, input.req);
    return { handled: true, action: 'already_absent', providerUserId };
  }

  const { hasPassword, identityCount } = await deps.getUserLoginState(account.userId);
  if (!hasPassword && identityCount <= 1) {
    await deps.markOAuthAccountDeauthorized(account.id, {
      provider: 'FACEBOOK',
      providerUserId,
      strategy: 'mark_deauthorized',
      reason: 'LAST_LOGIN_METHOD',
    });
    await deps.writeSecurityEvent(account.userId, {
      event: 'META_DEAUTHORIZE_CALLBACK',
      provider: 'FACEBOOK',
      providerUserIdKnown: true,
      strategy: 'mark_deauthorized',
      reason: 'LAST_LOGIN_METHOD',
    }, input.req);
    return { handled: true, action: 'marked_deauthorized', providerUserId, userId: account.userId };
  }

  await deps.unlinkOAuthAccount(account.id);
  await deps.writeAuditUnlinked(account.userId, providerUserId, input.req);
  await deps.writeSecurityEvent(account.userId, {
    event: 'META_DEAUTHORIZE_CALLBACK',
    provider: 'FACEBOOK',
    providerUserIdKnown: true,
    strategy: 'unlink',
  }, input.req);
  return { handled: true, action: 'unlinked', providerUserId, userId: account.userId };
}
