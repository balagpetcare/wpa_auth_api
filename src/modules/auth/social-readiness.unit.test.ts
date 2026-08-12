import test from 'node:test';
import assert from 'node:assert/strict';
import { OAuthProvider, SocialIdentityProviderEnvironment, SocialIdentityProviderPlacement, SocialIdentityProviderStatus } from '@prisma/client';
import { computeProviderReadiness } from './social-readiness.js';
import { appCallbackUrl } from './social-providers/base.js';

function facebookRow(overrides: Record<string, unknown> = {}) {
  return {
    provider: OAuthProvider.FACEBOOK,
    displayName: 'Facebook',
    clientId: '123456789012345',
    clientSecretEncrypted: '{"k":"v"}',
    authorizationUrl: 'https://www.facebook.com/v26.0/dialog/oauth',
    tokenUrl: 'https://graph.facebook.com/v26.0/oauth/access_token',
    userInfoUrl: 'https://graph.facebook.com/v26.0/me?fields=id,name,email,picture',
    scopes: ['email', 'public_profile'],
    redirectUri: appCallbackUrl(OAuthProvider.FACEBOOK),
    providerMetadata: {},
    status: SocialIdentityProviderStatus.INACTIVE,
    environment: SocialIdentityProviderEnvironment.LIVE,
    placement: SocialIdentityProviderPlacement.MAIN,
    sortOrder: 2,
    showOnLogin: false,
    lastTestAt: null,
    lastSuccessfulTestAt: null,
    lastTestStatus: null,
    lastTestError: null,
    ...overrides,
  } as any;
}

function instagramRow(overrides: Record<string, unknown> = {}) {
  return {
    provider: OAuthProvider.INSTAGRAM,
    displayName: 'Instagram',
    clientId: '1234567890123456',
    clientSecretEncrypted: '{"k":"v"}',
    authorizationUrl: 'https://api.instagram.com/oauth/authorize',
    tokenUrl: 'https://api.instagram.com/oauth/access_token',
    userInfoUrl: 'https://graph.instagram.com/v26.0/me?fields=id,username',
    scopes: ['instagram_business_basic'],
    redirectUri: appCallbackUrl(OAuthProvider.INSTAGRAM),
    providerMetadata: {
      integrationType: 'api_setup_with_instagram_login',
      professionalAccountOnlyWarning: true,
    },
    status: SocialIdentityProviderStatus.INACTIVE,
    environment: SocialIdentityProviderEnvironment.LIVE,
    placement: SocialIdentityProviderPlacement.MORE,
    sortOrder: 3,
    showOnLogin: false,
    lastTestAt: null,
    lastSuccessfulTestAt: null,
    lastTestStatus: null,
    lastTestError: null,
    ...overrides,
  } as any;
}

test('Facebook configuration can be testable while still blocked for public activation', () => {
  const readiness = computeProviderReadiness(facebookRow())
  assert.equal(readiness.configurationReady, true)
  assert.equal(readiness.canTest, true)
  assert.equal(readiness.tested, false)
  assert.equal(readiness.lifecycleStage, 'ADMIN_TESTABLE')
  assert.equal(readiness.readyForProduction, false)
  assert.ok(readiness.blockers.some((blocker) => blocker.includes('Test-login status')))
  assert.equal(readiness.testBlockers.length, 0)
})

test('Facebook readiness accepts NOT_REQUIRED metadata for optional external states', () => {
  const readiness = computeProviderReadiness(facebookRow({
    providerMetadata: {
      developerConsoleStatus: 'configured',
      appMode: 'live',
      appReviewStatus: 'not_required',
      businessVerificationStatus: 'not_required',
      verifiedDomainStatus: 'not_required',
      dataDeletionCallbackStatus: 'not_required',
    },
    lastSuccessfulTestAt: new Date('2026-08-12T00:00:00.000Z'),
    lastTestAt: new Date('2026-08-12T00:00:00.000Z'),
    lastTestStatus: 'SUCCESS',
  }))

  assert.equal(readiness.readyForProduction, true)
  assert.equal(readiness.lifecycleStage, 'PRODUCTION_READY')
  assert.equal(readiness.canActivate, true)
  assert.equal(readiness.blockers.length, 0)
})

test('Instagram configuration is testable with the Instagram Login scope and integration type', () => {
  const readiness = computeProviderReadiness(instagramRow())
  assert.equal(readiness.configurationReady, true)
  assert.equal(readiness.canTest, true)
  assert.equal(readiness.lifecycleStage, 'ADMIN_TESTABLE')
  assert.equal(readiness.testBlockers.length, 0)
  assert.ok(readiness.checks.some((check) => check.key === 'scopes' && check.status === 'OK'))
  assert.ok(readiness.checks.some((check) => check.key === 'integrationType' && check.status === 'OK'))
})

test('Instagram no longer requires OpenID or email scopes for basic login readiness', () => {
  const readiness = computeProviderReadiness(instagramRow({
    scopes: ['instagram_business_basic', 'instagram_business_manage_messages', 'instagram_business_manage_comments'],
  }))
  assert.equal(readiness.canTest, true)
  assert.equal(readiness.testBlockers.length, 0)
  assert.ok(!readiness.blockers.some((blocker) => /openid|email|profile/i.test(blocker)))
})

test('Instagram blocks test initiation when the integration type is missing', () => {
  const readiness = computeProviderReadiness(instagramRow({
    providerMetadata: {},
  }))
  assert.equal(readiness.canTest, false)
  assert.ok(readiness.testBlockers.includes('Integration type is not ready.'))
})
