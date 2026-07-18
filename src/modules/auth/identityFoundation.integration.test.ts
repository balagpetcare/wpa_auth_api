// Integration tests for the Furtail centralized-auth identity foundation:
// OAuthAccount uniqueness/duplicate prevention, refresh-token rotation, and
// session revocation. Runs against the real dev database configured via
// DATABASE_URL (same DB this API uses in development) and cleans up every
// row it creates.
import test from 'node:test';
import assert from 'node:assert/strict';
import type { Request } from 'express';
import { prisma } from '../../lib/db.js';
import { refreshTokens, revokeSessionFamily } from './auth.service.js';
import { hashToken, signRefreshToken, generateOpaqueToken, parseTtlToSeconds } from '../../lib/tokens.js';
import { config } from '../../config/index.js';

function fakeReq(): Request {
  return { ip: '127.0.0.1', socket: { remoteAddress: '127.0.0.1' }, headers: {} } as unknown as Request;
}

async function makeUser(suffix: string) {
  return prisma.user.create({
    data: {
      email: `identity-foundation-${suffix}@example.com`,
      status: 'ACTIVE',
      emailVerifiedAt: new Date(),
    },
  });
}

async function makeSessionAndRefreshToken(userId: string, clientDbId: string) {
  const session = await prisma.loginSession.create({
    data: {
      userId,
      clientId: clientDbId,
      sessionToken: generateOpaqueToken(),
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
    },
  });
  const raw = signRefreshToken(userId);
  const refreshToken = await prisma.refreshToken.create({
    data: {
      userId,
      clientId: clientDbId,
      tokenHash: hashToken(raw),
      scopes: ['openid', 'offline_access'],
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      familyId: session.id,
    },
  });
  return { session, refreshToken, raw };
}

async function getOrCreateTestClient() {
  const existing = await prisma.authClient.findFirst({ where: { clientId: 'furtail-mobile' } });
  if (existing) return existing;
  return prisma.authClient.create({
    data: {
      name: 'Identity Foundation Test Client',
      slug: `identity-foundation-test-${Date.now()}`,
      type: 'FIRST_PARTY_APP',
      clientId: `identity-foundation-test-${Date.now()}`,
      allowedOrigins: [],
      redirectUris: [],
      allowedScopes: [],
    },
  });
}

test('OAuthAccount enforces uniqueness on (provider, providerAccountId)', async () => {
  const user = await makeUser(`dup-${Date.now()}`);
  const providerAccountId = `dup-account-${Date.now()}`;

  await prisma.oAuthAccount.create({
    data: { userId: user.id, provider: 'GOOGLE', providerAccountId, emailVerifiedAt: new Date() },
  });

  await assert.rejects(
    () =>
      prisma.oAuthAccount.create({
        data: { userId: user.id, provider: 'GOOGLE', providerAccountId },
      }),
    (err: any) => err.code === 'P2002',
  );

  await prisma.oAuthAccount.deleteMany({ where: { userId: user.id } });
  await prisma.user.delete({ where: { id: user.id } });
});

test('a second user cannot claim an OAuthAccount identity already linked to another user', async () => {
  const owner = await makeUser(`owner-${Date.now()}`);
  const other = await makeUser(`other-${Date.now()}`);
  const providerAccountId = `claim-account-${Date.now()}`;

  await prisma.oAuthAccount.create({
    data: { userId: owner.id, provider: 'FACEBOOK', providerAccountId },
  });

  await assert.rejects(
    () =>
      prisma.oAuthAccount.create({
        data: { userId: other.id, provider: 'FACEBOOK', providerAccountId },
      }),
    (err: any) => err.code === 'P2002',
  );

  await prisma.oAuthAccount.deleteMany({ where: { userId: owner.id } });
  await prisma.user.deleteMany({ where: { id: { in: [owner.id, other.id] } } });
});

test('unverified email/phone on an identity never implies a duplicate account by itself', async () => {
  // Two different OAuthAccount rows (different providerAccountId) are allowed
  // to carry the SAME unverified email without any unique-constraint or
  // application-level conflict, because email/emailVerifiedAt on OAuthAccount
  // are informational only — never used as a merge key unless verified.
  const userA = await makeUser(`unverified-a-${Date.now()}`);
  const userB = await makeUser(`unverified-b-${Date.now()}`);
  const sharedEmail = `shared-unverified-${Date.now()}@example.com`;

  const accountA = await prisma.oAuthAccount.create({
    data: { userId: userA.id, provider: 'GITHUB', providerAccountId: `gh-a-${Date.now()}`, email: sharedEmail, emailVerifiedAt: null },
  });
  const accountB = await prisma.oAuthAccount.create({
    data: { userId: userB.id, provider: 'GITHUB', providerAccountId: `gh-b-${Date.now()}`, email: sharedEmail, emailVerifiedAt: null },
  });

  assert.notEqual(accountA.userId, accountB.userId);

  await prisma.oAuthAccount.deleteMany({ where: { id: { in: [accountA.id, accountB.id] } } });
  await prisma.user.deleteMany({ where: { id: { in: [userA.id, userB.id] } } });
});

test('refresh token rotation issues a new token and revokes the old one within the same family', async () => {
  const user = await makeUser(`rotate-${Date.now()}`);
  const client = await getOrCreateTestClient();
  const { session, refreshToken, raw } = await makeSessionAndRefreshToken(user.id, client.id);

  const result = await refreshTokens(raw, fakeReq());
  assert.ok(result.accessToken);
  assert.ok(result.refreshToken);
  assert.notEqual(result.refreshToken, raw);

  const oldRow = await prisma.refreshToken.findUnique({ where: { id: refreshToken.id } });
  assert.ok(oldRow?.revokedAt, 'old refresh token must be revoked after rotation');
  assert.equal(oldRow?.revocationReason, 'ROTATED');
  assert.ok(oldRow?.replacedByTokenId, 'old refresh token must reference its replacement');

  const newRow = await prisma.refreshToken.findUnique({ where: { tokenHash: hashToken(result.refreshToken) } });
  assert.ok(newRow, 'new refresh token row must exist');
  assert.equal(newRow?.familyId, session.id, 'rotated token stays in the same session family');
  assert.equal(newRow?.revokedAt, null);

  await prisma.refreshToken.deleteMany({ where: { userId: user.id } });
  await prisma.loginSession.deleteMany({ where: { userId: user.id } });
  await prisma.user.delete({ where: { id: user.id } });
});

test('reusing a rotated refresh token is detected and revokes the whole session family', async () => {
  const user = await makeUser(`reuse-${Date.now()}`);
  const client = await getOrCreateTestClient();
  const { session, raw } = await makeSessionAndRefreshToken(user.id, client.id);

  // First use rotates the token (old one becomes revoked/ROTATED).
  await refreshTokens(raw, fakeReq());

  // Reusing the now-rotated original token must be rejected...
  await assert.rejects(() => refreshTokens(raw, fakeReq()), (err: any) => err.code === 'REFRESH_TOKEN_REUSED');

  // ...and must revoke every refresh token / the session in that family,
  // including the newly-rotated one that was otherwise still valid.
  const familyTokens = await prisma.refreshToken.findMany({ where: { familyId: session.id } });
  assert.ok(familyTokens.length >= 2);
  assert.ok(familyTokens.every((t) => t.revokedAt !== null), 'all tokens in the family must be revoked after reuse is detected');

  const sessionRow = await prisma.loginSession.findUnique({ where: { id: session.id } });
  assert.ok(sessionRow?.revokedAt, 'session must be revoked after refresh-token reuse is detected');

  await prisma.refreshToken.deleteMany({ where: { userId: user.id } });
  await prisma.loginSession.deleteMany({ where: { userId: user.id } });
  await prisma.user.delete({ where: { id: user.id } });
});

test('revokeSessionFamily revokes the session and its refresh tokens (logout from one device)', async () => {
  const user = await makeUser(`logout-one-${Date.now()}`);
  const client = await getOrCreateTestClient();
  const { session, refreshToken } = await makeSessionAndRefreshToken(user.id, client.id);

  await revokeSessionFamily(user.id, session.id, 'USER_LOGOUT');

  const sessionRow = await prisma.loginSession.findUnique({ where: { id: session.id } });
  const tokenRow = await prisma.refreshToken.findUnique({ where: { id: refreshToken.id } });
  assert.ok(sessionRow?.revokedAt);
  assert.equal(sessionRow?.revocationReason, 'USER_LOGOUT');
  assert.ok(tokenRow?.revokedAt);

  await prisma.refreshToken.deleteMany({ where: { userId: user.id } });
  await prisma.loginSession.deleteMany({ where: { userId: user.id } });
  await prisma.user.delete({ where: { id: user.id } });
});

test('a token from a session revoked by another means (logout-all) is rejected on next refresh with SESSION_REVOKED', async () => {
  const user = await makeUser(`logout-all-${Date.now()}`);
  const client = await getOrCreateTestClient();
  const { session, raw } = await makeSessionAndRefreshToken(user.id, client.id);

  // Simulate "logout from all devices": revoke the session directly without
  // touching the refresh token row (mirrors an admin/security action that
  // revokes sessions out of band from the token's own revokedAt flag).
  await prisma.loginSession.update({ where: { id: session.id }, data: { revokedAt: new Date(), revocationReason: 'USER_LOGOUT_ALL' } });

  await assert.rejects(() => refreshTokens(raw, fakeReq()), (err: any) => err.code === 'SESSION_REVOKED');

  await prisma.refreshToken.deleteMany({ where: { userId: user.id } });
  await prisma.loginSession.deleteMany({ where: { userId: user.id } });
  await prisma.user.delete({ where: { id: user.id } });
});
