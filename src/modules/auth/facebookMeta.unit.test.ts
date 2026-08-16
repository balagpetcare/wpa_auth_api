import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import http from 'node:http';
import express from 'express';
import type { Request } from 'express';
import socialRoutes, { parseSocialCallbackQuery } from './social.routes.js';
import { verifyMetaSignedRequest } from '../../lib/metaSignedRequest.js';
import { handleFacebookDeauthorizeCallback } from './facebookDeauthorize.service.js';
import { handleCallback } from './social.service.js';
import { appCallbackUrl } from './social-providers/base.js';
import { FACEBOOK_GRAPH_API_VERSION, getFacebookAuthorizationUrl, getFacebookTokenUrl, getFacebookUserInfoUrl } from './facebookMetaConfig.js';
import { OAuthProvider } from '@prisma/client';
import { requestMetaDeletionFromDecoded } from '../deletion/deletion.service.js';
import { config } from '../../config/index.js';
import { verifyFacebookAccessToken } from './identity-providers/facebook.js';
import { prisma } from '../../lib/db.js';
import { encryptCredentialPayload } from '../../lib/credentialEncryption.js';

function signMetaPayload(payload: Record<string, unknown>, secret: string) {
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const encodedSignature = crypto.createHmac('sha256', secret).update(encodedPayload).digest('base64url');
  return `${encodedSignature}.${encodedPayload}`;
}

function fakeReq(): Request {
  return {
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    headers: {},
  } as unknown as Request;
}

async function startSocialRouterServer() {
  const app = express();
  app.use(express.json());
  app.use('/auth/social', socialRoutes);
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(err?.statusCode ?? err?.status ?? 500).json({
      success: false,
      code: err?.code ?? 'INTERNAL_SERVER_ERROR',
      message: err?.message ?? 'Internal Server Error',
    });
  });
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

test('direct Facebook OAuth callback visit without code/state returns the expected 400 response', async () => {
  const { server, baseUrl } = await startSocialRouterServer();
  try {
    const res = await fetch(`${baseUrl}/auth/social/facebook/callback`);
    assert.equal(res.status, 400);
    assert.deepEqual(await res.json(), {
      success: false,
      message: 'Missing code or state.',
    });
  } finally {
    server.close();
  }
});

test('parseSocialCallbackQuery rejects missing code/state', () => {
  assert.equal(parseSocialCallbackQuery({}), null);
  assert.equal(parseSocialCallbackQuery({ code: 'abc' }), null);
});

test('browser-client social callback cancellation redirects back to the requesting redirect_uri with the original app state', async () => {
  const state = jwt.sign({
    provider: 'GOOGLE',
    purpose: 'SOCIAL_LOGIN',
    nonce: 'nonce-1',
    redirectContext: {
      client_id: 'bangladesh_pet_association_client_id',
      redirect_uri: 'https://api.bangladeshpetassociation.com/api/v1/auth/central-auth/callback',
      state: 'bpa-client-state',
    },
  }, config.JWT_ACCESS_SECRET, { expiresIn: '10m' });

  const { server, baseUrl } = await startSocialRouterServer();
  try {
    const res = await fetch(`${baseUrl}/auth/social/google/callback?error=access_denied&state=${encodeURIComponent(state)}`, {
      redirect: 'manual',
    });
    assert.equal(res.status, 302);
    assert.equal(
      res.headers.get('location'),
      'https://api.bangladeshpetassociation.com/api/v1/auth/central-auth/callback?error=access_denied&state=bpa-client-state',
    );
  } finally {
    server.close();
  }
});

test('handleCallback rejects tampered or invalid social OAuth state', async () => {
  await assert.rejects(
    () => handleCallback('facebook', 'provider-code', 'tampered-state', fakeReq()),
    (err: any) => err.code === 'INVALID_STATE',
  );
});

test('handleCallback records a real admin Facebook test success without issuing WPA tokens', async () => {
  const now = new Date('2026-08-12T13:45:00.000Z');
  const state = jwt.sign({
    provider: 'FACEBOOK',
    purpose: 'ADMIN_PROVIDER_TEST',
    providerConfigId: 'provider-1',
    adminId: 'admin-1',
    returnTo: 'https://auth-admin.worldpetsassociation.com/authentication/social-providers',
  }, config.JWT_ACCESS_SECRET, { expiresIn: '10m' });
  const row = {
    id: 'provider-1',
    provider: 'FACEBOOK',
    displayName: 'Facebook',
    clientId: '123456789012345',
    clientSecretEncrypted: JSON.stringify(encryptCredentialPayload({ clientSecret: 'secret' })),
    authorizationUrl: 'https://www.facebook.com/v26.0/dialog/oauth',
    tokenUrl: 'https://graph.facebook.com/v26.0/oauth/access_token',
    userInfoUrl: 'https://graph.facebook.com/v26.0/me?fields=id,name,email,picture',
    scopes: ['email', 'public_profile'],
    redirectUri: appCallbackUrl(OAuthProvider.FACEBOOK),
    providerMetadata: {},
    status: 'INACTIVE',
    environment: 'LIVE',
    placement: 'MAIN',
    sortOrder: 2,
    showOnLogin: false,
    lastTestAt: null,
    lastSuccessfulTestAt: null,
    lastTestStatus: null,
    lastTestError: null,
  } as any;
  const updateCalls: any[] = [];
  const originalFindUnique = prisma.socialIdentityProviderConfig.findUnique;
  const originalUpdate = prisma.socialIdentityProviderConfig.update;
  const originalAuditCreate = prisma.auditLog.create;
  const originalUserCreate = prisma.user.create;
  const originalLoginSessionCreate = prisma.loginSession.create;
  const originalRefreshTokenCreate = prisma.refreshToken.create;
  const originalUserUpdate = prisma.user.update;
  const originalOAuthAccountCreate = prisma.oAuthAccount.create;
  const originalOAuthAccountUpdate = prisma.oAuthAccount.update;
  const originalFetch = globalThis.fetch;
  (prisma as any).socialIdentityProviderConfig.findUnique = async () => row;
  (prisma as any).socialIdentityProviderConfig.update = async (args: any) => {
    updateCalls.push(args);
    return { ...row, ...args.data };
  };
  (prisma as any).auditLog.create = async () => undefined;
  (prisma as any).user.create = async () => { throw new Error('user creation should not happen for admin provider tests'); };
  (prisma as any).loginSession.create = async () => { throw new Error('login session creation should not happen for admin provider tests'); };
  (prisma as any).refreshToken.create = async () => { throw new Error('refresh token creation should not happen for admin provider tests'); };
  (prisma as any).user.update = async () => { throw new Error('user update should not happen for admin provider tests'); };
  (prisma as any).oAuthAccount.create = async () => { throw new Error('oauth account creation should not happen for admin provider tests'); };
  (prisma as any).oAuthAccount.update = async () => { throw new Error('oauth account update should not happen for admin provider tests'); };
  const fetchCalls: string[] = [];
  globalThis.fetch = (async (input: any) => {
    fetchCalls.push(String(input));
    if (fetchCalls.length === 1) {
      return {
        ok: true,
        json: async () => ({ access_token: 'fb-user-token' }),
      } as Response;
    }
    return {
      ok: true,
      json: async () => ({ id: 'fb-user-1', name: 'Facebook Tester', email: 'tester@example.com', picture: { data: { url: 'https://example.com/avatar.png' } } }),
    } as Response;
  }) as unknown as typeof fetch;
  try {
    const result = await handleCallback('facebook', 'provider-code', state, fakeReq())
    assert.equal(result.kind, 'ADMIN_TEST_COMPLETE')
    assert.equal(result.provider, 'FACEBOOK')
    assert.match(result.redirectUrl, /auth-admin\.worldpetsassociation\.com\/authentication\/social-providers/)
    assert.match(result.redirectUrl, /test=success/)
    assert.equal(updateCalls.length, 1)
    assert.equal(updateCalls[0].data.lastTestStatus, 'SUCCESS')
    assert.ok(updateCalls[0].data.lastSuccessfulTestAt instanceof Date)
    assert.equal(fetchCalls.length, 2)
  } finally {
    globalThis.fetch = originalFetch;
    (prisma as any).socialIdentityProviderConfig.findUnique = originalFindUnique;
    (prisma as any).socialIdentityProviderConfig.update = originalUpdate;
    (prisma as any).auditLog.create = originalAuditCreate;
    (prisma as any).user.create = originalUserCreate;
    (prisma as any).loginSession.create = originalLoginSessionCreate;
    (prisma as any).refreshToken.create = originalRefreshTokenCreate;
    (prisma as any).user.update = originalUserUpdate;
    (prisma as any).oAuthAccount.create = originalOAuthAccountCreate;
    (prisma as any).oAuthAccount.update = originalOAuthAccountUpdate;
  }
});

test('Facebook OAuth callback URL generation uses the mounted production path shape', () => {
  assert.equal(
    appCallbackUrl(OAuthProvider.FACEBOOK),
    'https://auth.worldpetsassociation.com/api/v1/auth/social/facebook/callback',
  );
});

test('Facebook OAuth defaults use the current Meta Graph API version', () => {
  assert.equal(FACEBOOK_GRAPH_API_VERSION, 'v26.0');
  assert.equal(getFacebookAuthorizationUrl(), 'https://www.facebook.com/v26.0/dialog/oauth');
  assert.equal(getFacebookTokenUrl(), 'https://graph.facebook.com/v26.0/oauth/access_token');
  assert.equal(getFacebookUserInfoUrl(), 'https://graph.facebook.com/v26.0/me?fields=id,name,email,picture');
});

test('verifyMetaSignedRequest accepts a valid Meta signed_request', () => {
  const secret = 'meta-secret';
  const signedRequest = signMetaPayload({
    algorithm: 'HMAC-SHA256',
    issued_at: Math.floor(Date.now() / 1000),
    user_id: 'fb-user-1',
  }, secret);
  const payload = verifyMetaSignedRequest(signedRequest, secret);
  assert.equal(payload.user_id, 'fb-user-1');
});

test('verifyMetaSignedRequest rejects malformed signed_request input', () => {
  assert.throws(
    () => verifyMetaSignedRequest('not-a-signed-request', 'meta-secret'),
    (err: any) => err.code === 'VALIDATION_ERROR',
  );
});

test('verifyMetaSignedRequest rejects invalid signatures', () => {
  const secret = 'meta-secret';
  const signedRequest = signMetaPayload({
    algorithm: 'HMAC-SHA256',
    user_id: 'fb-user-1',
  }, 'different-secret');
  assert.throws(
    () => verifyMetaSignedRequest(signedRequest, secret),
    (err: any) => err.code === 'FORBIDDEN',
  );
});

test('verifyMetaSignedRequest rejects unsupported algorithms', () => {
  const secret = 'meta-secret';
  const signedRequest = signMetaPayload({
    algorithm: 'HMAC-SHA1',
    user_id: 'fb-user-1',
  }, secret);
  assert.throws(
    () => verifyMetaSignedRequest(signedRequest, secret),
    (err: any) => err.code === 'VALIDATION_ERROR',
  );
});

test('Facebook deauthorize callback is idempotent for unknown users', async () => {
  const secret = 'meta-secret';
  const result = await handleFacebookDeauthorizeCallback({
    signedRequest: signMetaPayload({ algorithm: 'HMAC-SHA256', user_id: 'missing-user' }, secret),
    req: fakeReq(),
  }, {
    verifySignedRequest: (signedRequest) => verifyMetaSignedRequest(signedRequest, secret),
    findFacebookAccountByProviderUserId: async () => null,
    getUserLoginState: async () => ({ hasPassword: false, identityCount: 0 }),
    unlinkOAuthAccount: async () => undefined,
    markOAuthAccountDeauthorized: async () => undefined,
    writeAuditUnlinked: async () => undefined,
    writeSecurityEvent: async () => undefined,
  });
  assert.deepEqual(result, { handled: true, action: 'already_absent', providerUserId: 'missing-user' });
});

test('Facebook deauthorize callback unlinks when another login path exists', async () => {
  const secret = 'meta-secret';
  const calls: string[] = [];
  const result = await handleFacebookDeauthorizeCallback({
    signedRequest: signMetaPayload({ algorithm: 'HMAC-SHA256', user_id: 'fb-user-2' }, secret),
    req: fakeReq(),
  }, {
    verifySignedRequest: (signedRequest) => verifyMetaSignedRequest(signedRequest, secret),
    findFacebookAccountByProviderUserId: async () => ({ id: 'oa-1', userId: 'user-1', rawProfile: null }),
    getUserLoginState: async () => ({ hasPassword: true, identityCount: 1 }),
    unlinkOAuthAccount: async () => { calls.push('unlink'); },
    markOAuthAccountDeauthorized: async () => { calls.push('mark'); },
    writeAuditUnlinked: async () => { calls.push('audit'); },
    writeSecurityEvent: async () => { calls.push('security'); },
  });
  assert.equal(result.action, 'unlinked');
  assert.deepEqual(calls, ['unlink', 'audit', 'security']);
});

test('Facebook deauthorize callback preserves the last login path by marking deauthorized instead of unlinking', async () => {
  const secret = 'meta-secret';
  const calls: string[] = [];
  const result = await handleFacebookDeauthorizeCallback({
    signedRequest: signMetaPayload({ algorithm: 'HMAC-SHA256', user_id: 'fb-user-3' }, secret),
    req: fakeReq(),
  }, {
    verifySignedRequest: (signedRequest) => verifyMetaSignedRequest(signedRequest, secret),
    findFacebookAccountByProviderUserId: async () => ({ id: 'oa-1', userId: 'user-1', rawProfile: null }),
    getUserLoginState: async () => ({ hasPassword: false, identityCount: 1 }),
    unlinkOAuthAccount: async () => { calls.push('unlink'); },
    markOAuthAccountDeauthorized: async () => { calls.push('mark'); },
    writeAuditUnlinked: async () => { calls.push('audit'); },
    writeSecurityEvent: async () => { calls.push('security'); },
  });
  assert.equal(result.action, 'marked_deauthorized');
  assert.deepEqual(calls, ['mark', 'security']);
});

test('Facebook deauthorize callback rejects signed_request payloads without a provider user id', async () => {
  const secret = 'meta-secret';
  await assert.rejects(
    () => handleFacebookDeauthorizeCallback({
      signedRequest: signMetaPayload({ algorithm: 'HMAC-SHA256' }, secret),
      req: fakeReq(),
    }, {
      verifySignedRequest: (signedRequest) => verifyMetaSignedRequest(signedRequest, secret),
      findFacebookAccountByProviderUserId: async () => null,
      getUserLoginState: async () => ({ hasPassword: false, identityCount: 0 }),
      unlinkOAuthAccount: async () => undefined,
      markOAuthAccountDeauthorized: async () => undefined,
      writeAuditUnlinked: async () => undefined,
      writeSecurityEvent: async () => undefined,
    }),
    (err: any) => err.code === 'VALIDATION_ERROR',
  );
});

test('Meta deletion callback creates and processes a provider-data deletion request for a known Facebook user', async () => {
  const req = fakeReq();
  const result = await requestMetaDeletionFromDecoded({
    algorithm: 'HMAC-SHA256',
    user_id: 'fb-user-4',
  }, req, {
    findUserIdByProviderAccountId: async (providerAccountId) => providerAccountId === 'fb-user-4' ? 'user-4' : null,
    findUserIdByEmail: async () => null,
    createDeletionRequest: async (input: any) => ({
      id: 'dr-1',
      confirmationCode: 'confirm-123',
      requestType: input.requestType,
      provider: input.provider,
      requestSource: input.requestSource,
      status: input.status,
      userId: input.userId,
      emailHash: null,
      emailReference: null,
      requestedAt: new Date(),
      gracePeriodDeadlineAt: input.gracePeriodDeadlineAt,
      processedAt: null,
      cancelledAt: null,
      reviewedAt: null,
      failureReason: null,
      sourceIp: null,
      sourceUserAgent: null,
      auditMetadata: null,
      user: null,
      events: [],
      metaPayload: input.metaPayload,
      updatedAt: new Date(),
      cancelledByUserId: null,
      cancelledByAdminId: null,
      reviewedByAdminId: null,
    }),
    processDeletionRequest: async () => ({ status: 'COMPLETED' } as any),
  });
  assert.equal(result.confirmation_code, 'confirm-123');
  assert.match(result.url, /\/data-deletion\/status\/confirm-123$/);
  assert.equal(result.status, 'COMPLETED');
});

test('Meta deletion callback safely handles an unknown Facebook user id', async () => {
  const req = fakeReq();
  const result = await requestMetaDeletionFromDecoded({
    algorithm: 'HMAC-SHA256',
    user_id: 'fb-missing',
  }, req, {
    findUserIdByProviderAccountId: async () => null,
    findUserIdByEmail: async () => null,
    createDeletionRequest: async (input: any) => ({
      id: 'dr-2',
      confirmationCode: 'confirm-unknown',
      requestType: input.requestType,
      provider: input.provider,
      requestSource: input.requestSource,
      status: input.status,
      userId: input.userId,
      emailHash: null,
      emailReference: null,
      requestedAt: new Date(),
      gracePeriodDeadlineAt: input.gracePeriodDeadlineAt,
      processedAt: null,
      cancelledAt: null,
      reviewedAt: null,
      failureReason: null,
      sourceIp: null,
      sourceUserAgent: null,
      auditMetadata: null,
      user: null,
      events: [],
      metaPayload: input.metaPayload,
      updatedAt: new Date(),
      cancelledByUserId: null,
      cancelledByAdminId: null,
      reviewedByAdminId: null,
    }),
    processDeletionRequest: async () => ({ status: 'COMPLETED' } as any),
  });
  assert.equal(result.confirmation_code, 'confirm-unknown');
  assert.equal(result.status, 'COMPLETED');
});

test('Facebook identity verification rejects invalid token/profile responses without leaking secrets', async () => {
  const originalFetch = globalThis.fetch;
  const originalAppId = config.FACEBOOK_APP_ID;
  const originalAppSecret = config.FACEBOOK_APP_SECRET;
  (config as any).FACEBOOK_APP_ID = 'app-id';
  (config as any).FACEBOOK_APP_SECRET = 'app-secret';
  globalThis.fetch = (async () => ({
    ok: false,
    status: 400,
    statusText: 'Bad Request',
    headers: new Headers(),
    redirected: false,
    type: 'basic',
    url: 'https://graph.facebook.com/mock',
    body: null,
    bodyUsed: false,
    clone() { return this as Response; },
    arrayBuffer: async () => new ArrayBuffer(0),
    blob: async () => new Blob([]),
    bytes: async () => new Uint8Array(),
    formData: async () => new FormData(),
    text: async () => JSON.stringify({ error: { message: 'bad token app-secret should never leak' } }),
    json: async () => ({ error: { message: 'bad token app-secret should never leak' } }),
  })) as unknown as typeof fetch;
  try {
    await assert.rejects(
      () => verifyFacebookAccessToken('bad-token-value'),
      (err: any) => err.code === 'INVALID_PROVIDER_TOKEN'
        && !String(err.message).includes('bad-token-value')
        && !String(err.message).includes('app-secret'),
    );
  } finally {
    globalThis.fetch = originalFetch;
    (config as any).FACEBOOK_APP_ID = originalAppId;
    (config as any).FACEBOOK_APP_SECRET = originalAppSecret;
  }
});
