import test from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import type { Prisma } from '@prisma/client';
import { encryptCredentialPayload } from '../../lib/credentialEncryption.js';
import { config } from '../../config/index.js';
import { prisma } from '../../lib/db.js';
import { updateSocialProvider, updateSocialProviderStatus } from './admin.service.js';
import { testProvider as testSocialProvider } from '../auth/social.service.js';

function makeEncryptedSecret(value: string) {
  return JSON.stringify(encryptCredentialPayload({ clientSecret: value }));
}

function baseProvider(overrides: Partial<Prisma.SocialIdentityProviderConfigGetPayload<{}>> = {}) {
  return {
    id: 'provider-1',
    provider: 'FACEBOOK',
    displayName: 'Facebook',
    clientId: '1234567890',
    clientSecretEncrypted: makeEncryptedSecret('old-secret'),
    authorizationUrl: 'https://www.facebook.com/v26.0/dialog/oauth',
    tokenUrl: 'https://graph.facebook.com/v26.0/oauth/access_token',
    userInfoUrl: 'https://graph.facebook.com/v26.0/me?fields=id,name,email,picture',
    scopes: ['email', 'public_profile'],
    redirectUri: 'https://auth.worldpetsassociation.com/api/v1/auth/social/facebook/callback',
    providerMetadata: null,
    status: 'INACTIVE',
    environment: 'LIVE',
    placement: 'MAIN',
    sortOrder: 2,
    showOnLogin: false,
    lastTestAt: null,
    lastSuccessfulTestAt: null,
    lastTestStatus: null,
    lastTestError: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    createdByAdminId: null,
    updatedByAdminId: null,
    ...overrides,
  } as any
}

function googleProvider(overrides: Partial<Prisma.SocialIdentityProviderConfigGetPayload<{}>> = {}) {
  return baseProvider({
    id: 'google-provider-1',
    provider: 'GOOGLE',
    displayName: 'Google',
    clientId: 'google-client-id',
    authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: ['openid', 'email', 'profile'],
    redirectUri: 'https://auth.worldpetsassociation.com/api/v1/auth/social/google/callback',
    providerMetadata: {},
    ...overrides,
  })
}

test('updateSocialProvider preserves the existing secret when Replace Secret is blank', async (t) => {
  const existing = baseProvider()
  const updateCalls: any[] = []
  const originalFindUnique = prisma.socialIdentityProviderConfig.findUnique
  const originalUpdate = prisma.socialIdentityProviderConfig.update
  const originalAuditCreate = prisma.auditLog.create
  ;(prisma.socialIdentityProviderConfig.findUnique as any) = async () => existing
  ;(prisma.socialIdentityProviderConfig.update as any) = async (args: any) => {
    updateCalls.push(args)
    return { ...existing, ...args.data }
  }
  ;(prisma.auditLog.create as any) = async () => undefined
  try {
    const result = await updateSocialProvider(existing.id, {
      displayName: existing.displayName,
      clientId: existing.clientId,
      authorizationUrl: existing.authorizationUrl,
      tokenUrl: existing.tokenUrl,
      userInfoUrl: existing.userInfoUrl,
      scopes: existing.scopes,
      redirectUri: existing.redirectUri,
      status: existing.status,
      environment: existing.environment,
      placement: existing.placement,
      sortOrder: existing.sortOrder,
      showOnLogin: existing.showOnLogin,
    }, 'admin-1')

    assert.equal(updateCalls.length, 1)
    assert.equal(updateCalls[0].data.provider, 'FACEBOOK')
    assert.equal(updateCalls[0].data.clientSecretEncrypted, existing.clientSecretEncrypted)
    assert.equal(result.clientSecretEncrypted, undefined)
  } finally {
    ;(prisma.socialIdentityProviderConfig.findUnique as any) = originalFindUnique
    ;(prisma.socialIdentityProviderConfig.update as any) = originalUpdate
    ;(prisma.auditLog.create as any) = originalAuditCreate
  }
})

test('updateSocialProvider replaces the encrypted secret when a new secret is submitted', async (t) => {
  const existing = baseProvider()
  const updateCalls: any[] = []
  const originalFindUnique = prisma.socialIdentityProviderConfig.findUnique
  const originalUpdate = prisma.socialIdentityProviderConfig.update
  const originalAuditCreate = prisma.auditLog.create
  ;(prisma.socialIdentityProviderConfig.findUnique as any) = async () => existing
  ;(prisma.socialIdentityProviderConfig.update as any) = async (args: any) => {
    updateCalls.push(args)
    return { ...existing, ...args.data }
  }
  ;(prisma.auditLog.create as any) = async () => undefined
  try {
    await updateSocialProvider(existing.id, {
      displayName: existing.displayName,
      clientId: existing.clientId,
      clientSecret: 'new-secret',
      authorizationUrl: existing.authorizationUrl,
      tokenUrl: existing.tokenUrl,
      userInfoUrl: existing.userInfoUrl,
      scopes: existing.scopes,
      redirectUri: existing.redirectUri,
      status: existing.status,
      environment: existing.environment,
      placement: existing.placement,
      sortOrder: existing.sortOrder,
      showOnLogin: existing.showOnLogin,
    }, 'admin-1')

    assert.equal(updateCalls.length, 1)
    assert.equal(updateCalls[0].data.provider, 'FACEBOOK')
    assert.notEqual(updateCalls[0].data.clientSecretEncrypted, existing.clientSecretEncrypted)
    assert.ok(typeof updateCalls[0].data.clientSecretEncrypted === 'string')
  } finally {
    ;(prisma.socialIdentityProviderConfig.findUnique as any) = originalFindUnique
    ;(prisma.socialIdentityProviderConfig.update as any) = originalUpdate
    ;(prisma.auditLog.create as any) = originalAuditCreate
  }
})

test('updateSocialProviderStatus rejects premature activation with PROVIDER_NOT_READY and leaves the row unchanged', async () => {
  const existing = baseProvider({
    status: 'INACTIVE',
    lastSuccessfulTestAt: null,
    providerMetadata: {
      developerConsoleStatus: 'configured',
      appMode: 'live',
      appReviewStatus: 'not_required',
      businessVerificationStatus: 'not_required',
      verifiedDomainStatus: 'not_required',
      dataDeletionCallbackStatus: 'not_required',
    },
  })
  const originalFindUnique = prisma.socialIdentityProviderConfig.findUnique
  const originalUpdate = prisma.socialIdentityProviderConfig.update
  ;(prisma.socialIdentityProviderConfig.findUnique as any) = async () => existing
  let updateCalled = false
  ;(prisma.socialIdentityProviderConfig.update as any) = async () => {
    updateCalled = true
    throw new Error('should not update blocked provider')
  }
  try {
    await assert.rejects(
      () => updateSocialProviderStatus(existing.id, 'ACTIVE', 'admin-1'),
      (err: any) => {
        assert.equal(err.code, 'PROVIDER_NOT_READY')
        assert.ok(Array.isArray(err.details?.blockers))
        assert.ok((err.details?.blockers as string[]).some((blocker) => blocker.includes('Test-login status')))
        return true
      },
    )
    assert.equal(updateCalled, false)
  } finally {
    ;(prisma.socialIdentityProviderConfig.findUnique as any) = originalFindUnique
    ;(prisma.socialIdentityProviderConfig.update as any) = originalUpdate
  }
})

test('testProvider returns an OAuth test URL for an inactive but testable provider', async () => {
  const existing = baseProvider({
    status: 'INACTIVE',
    providerMetadata: {
      developerConsoleStatus: 'configured',
      appMode: 'live',
      appReviewStatus: 'not_required',
      businessVerificationStatus: 'not_required',
      verifiedDomainStatus: 'not_required',
      dataDeletionCallbackStatus: 'not_required',
    },
  })
  const originalFindUnique = prisma.socialIdentityProviderConfig.findUnique
  const originalUpdate = prisma.socialIdentityProviderConfig.update
  const originalAuditCreate = prisma.auditLog.create
  ;(prisma.socialIdentityProviderConfig.findUnique as any) = async () => existing
  ;(prisma.socialIdentityProviderConfig.update as any) = async () => {
    throw new Error('testProvider should not persist test timestamps before the OAuth callback succeeds')
  }
  ;(prisma.auditLog.create as any) = async () => undefined
  try {
    const result = await testSocialProvider(existing.id, 'admin-1')
    assert.equal(result.provider, 'FACEBOOK')
    assert.equal(result.readiness.canTest, true)
    assert.equal(typeof result.testUrl, 'string')
    assert.match(result.testUrl, /facebook\.com\/v26\.0\/dialog\/oauth/)
    assert.match(result.testUrl, /state=/)
  } finally {
    ;(prisma.socialIdentityProviderConfig.findUnique as any) = originalFindUnique
    ;(prisma.socialIdentityProviderConfig.update as any) = originalUpdate
    ;(prisma.auditLog.create as any) = originalAuditCreate
  }
})

test('testProvider resolves Google using the Google provider row and signs GOOGLE state', async () => {
  const existing = googleProvider({
    status: 'INACTIVE',
    providerMetadata: {
      developerConsoleStatus: 'configured',
      appMode: 'development',
    },
  })
  const originalFindUnique = prisma.socialIdentityProviderConfig.findUnique
  const originalUpdate = prisma.socialIdentityProviderConfig.update
  const originalAuditCreate = prisma.auditLog.create
  ;(prisma.socialIdentityProviderConfig.findUnique as any) = async () => existing
  ;(prisma.socialIdentityProviderConfig.update as any) = async () => {
    throw new Error('testProvider should not persist test timestamps before the OAuth callback succeeds')
  }
  ;(prisma.auditLog.create as any) = async () => undefined
  try {
    const result = await testSocialProvider(existing.id, 'admin-1')
    assert.equal(result.provider, 'GOOGLE')
    assert.match(result.testUrl, /accounts\.google\.com\/o\/oauth2\/v2\/auth/)
    assert.match(result.testUrl, /redirect_uri=https%3A%2F%2Fauth\.worldpetsassociation\.com%2Fapi%2Fv1%2Fauth%2Fsocial%2Fgoogle%2Fcallback/)
    assert.match(result.testUrl, /scope=openid\+email\+profile/)
    const state = new URL(result.testUrl).searchParams.get('state')
    assert.ok(state)
    const payload = jwt.verify(state as string, config.JWT_ACCESS_SECRET) as { provider?: string; purpose?: string; providerConfigId?: string }
    assert.equal(payload.provider, 'GOOGLE')
    assert.equal(payload.purpose, 'ADMIN_PROVIDER_TEST')
    assert.equal(payload.providerConfigId, existing.id)
  } finally {
    ;(prisma.socialIdentityProviderConfig.findUnique as any) = originalFindUnique
    ;(prisma.socialIdentityProviderConfig.update as any) = originalUpdate
    ;(prisma.auditLog.create as any) = originalAuditCreate
  }
})
