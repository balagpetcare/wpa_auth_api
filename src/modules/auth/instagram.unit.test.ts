import test from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import type { Request } from 'express';
import { OAuthProvider } from '@prisma/client';
import { instagramAdapter } from './social-providers/index.js';
import { appCallbackUrl } from './social-providers/base.js';
import { config } from '../../config/index.js';
import { prisma } from '../../lib/db.js';
import { encryptCredentialPayload } from '../../lib/credentialEncryption.js';
import { handleCallback } from './social.service.js';

function fakeReq(): Request {
  return {
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    headers: {},
  } as unknown as Request;
}

test('Instagram authorization URL uses the configured scope, redirect URI, and signed state', () => {
  const state = jwt.sign({ provider: 'INSTAGRAM', purpose: 'ADMIN_PROVIDER_TEST', providerConfigId: 'provider-1' }, config.JWT_ACCESS_SECRET, { expiresIn: '10m' });
  const url = instagramAdapter.buildAuthorizationUrl({
    provider: OAuthProvider.INSTAGRAM,
    displayName: 'Instagram',
    clientId: 'instagram-client-id',
    clientSecretEncrypted: JSON.stringify(encryptCredentialPayload({ clientSecret: 'secret' })),
    authorizationUrl: 'https://api.instagram.com/oauth/authorize',
    tokenUrl: 'https://api.instagram.com/oauth/access_token',
    userInfoUrl: 'https://graph.instagram.com/v26.0/me?fields=id,username',
    scopes: ['instagram_business_basic'],
    redirectUri: appCallbackUrl(OAuthProvider.INSTAGRAM),
    providerMetadata: {},
    status: 'INACTIVE',
    environment: 'LIVE',
    placement: 'MORE',
    sortOrder: 3,
    showOnLogin: false,
    createdAt: new Date(),
    updatedAt: new Date(),
    createdByAdminId: null,
    updatedByAdminId: null,
  } as any, state)
  assert.match(url, /api\.instagram\.com\/oauth\/authorize/)
  assert.match(url, /client_id=instagram-client-id/)
  assert.match(url, /redirect_uri=https%3A%2F%2Fauth\.worldpetsassociation\.com%2Fapi%2Fv1%2Fauth%2Fsocial%2Finstagram%2Fcallback/)
  assert.match(url, /scope=instagram_business_basic/)
  assert.match(url, /state=/)
})

test('Instagram token exchange sends the client secret server-side and fetches profile with access_token', async () => {
  const fetchCalls: Array<{ url: string; init?: RequestInit }> = []
  const originalFetch = globalThis.fetch
  globalThis.fetch = (async (input: any, init?: any) => {
    fetchCalls.push({ url: String(input), init })
    if (fetchCalls.length === 1) {
      const body = String(init?.body ?? '')
      assert.match(body, /client_secret=secret/)
      assert.match(body, /grant_type=authorization_code/)
      return { ok: true, json: async () => ({ access_token: 'instagram-user-token' }) } as Response
    }
    assert.match(String(input), /graph\.instagram\.com\/v26\.0\/me/)
    assert.match(String(input), /access_token=instagram-user-token/)
    return { ok: true, json: async () => ({ id: 'ig-user-1', username: 'instagram.tester' }) } as Response
  }) as unknown as typeof fetch

  try {
    const row = {
      id: 'instagram-provider-1',
      provider: OAuthProvider.INSTAGRAM,
      displayName: 'Instagram',
      clientId: 'instagram-client-id',
      clientSecretEncrypted: JSON.stringify(encryptCredentialPayload({ clientSecret: 'secret' })),
      authorizationUrl: 'https://api.instagram.com/oauth/authorize',
      tokenUrl: 'https://api.instagram.com/oauth/access_token',
      userInfoUrl: 'https://graph.instagram.com/v26.0/me?fields=id,username',
      scopes: ['instagram_business_basic'],
      redirectUri: appCallbackUrl(OAuthProvider.INSTAGRAM),
      providerMetadata: { integrationType: 'api_setup_with_instagram_login' },
      status: 'INACTIVE',
      environment: 'LIVE',
      placement: 'MORE',
      sortOrder: 3,
      showOnLogin: false,
      lastTestAt: null,
      lastSuccessfulTestAt: null,
      lastTestStatus: null,
      lastTestError: null,
    } as any
    ;(prisma as any).socialIdentityProviderConfig.findUnique = async () => row
    ;(prisma as any).socialIdentityProviderConfig.update = async (args: any) => ({ ...row, ...args.data })

    const state = jwt.sign({
      provider: 'INSTAGRAM',
      purpose: 'ADMIN_PROVIDER_TEST',
      providerConfigId: row.id,
      returnTo: 'https://auth-admin.worldpetsassociation.com/authentication/social-providers',
    }, config.JWT_ACCESS_SECRET, { expiresIn: '10m' })

    try {
      const result = await handleCallback('instagram', 'code-123', state, fakeReq())
      assert.equal(result.kind, 'ADMIN_TEST_COMPLETE')
      assert.equal(result.provider, 'INSTAGRAM')
      assert.match(result.redirectUrl, /test=success/)
      assert.equal(fetchCalls.length, 2)
    } finally {
      // No Prisma state is restored here because the test process exits after the file completes.
    }
  } finally {
    globalThis.fetch = originalFetch
  }
})
