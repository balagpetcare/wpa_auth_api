import test from 'node:test';
import assert from 'node:assert/strict';
import { OAuthProvider, SocialIdentityProviderEnvironment, SocialIdentityProviderPlacement, SocialIdentityProviderStatus } from '@prisma/client';
import { appCallbackUrl } from './social-providers/base.js';
import { publicBootstrapProviderFromConfig } from './bootstrap.service.js';

function providerRow(overrides: Record<string, unknown> = {}) {
  return {
    provider: OAuthProvider.GOOGLE,
    displayName: 'Google',
    clientId: 'google-client-id',
    clientSecretEncrypted: '{"encrypted":"secret"}',
    authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: ['openid', 'email', 'profile'],
    redirectUri: appCallbackUrl(OAuthProvider.GOOGLE),
    providerMetadata: {
      oauthConsentScreenStatus: 'approved',
      authorizedDomainStatus: 'verified',
      verificationStatus: 'approved',
    },
    status: SocialIdentityProviderStatus.ACTIVE,
    environment: SocialIdentityProviderEnvironment.LIVE,
    placement: SocialIdentityProviderPlacement.MAIN,
    sortOrder: 1,
    showOnLogin: true,
    lastTestAt: new Date('2026-08-12T00:00:00.000Z'),
    lastSuccessfulTestAt: new Date('2026-08-12T00:00:00.000Z'),
    lastTestStatus: 'SUCCESS',
    lastTestError: null,
    ...overrides,
  } as any;
}

test('public bootstrap provider exposes only safe metadata for ready providers', () => {
  const provider = publicBootstrapProviderFromConfig(providerRow());

  assert.deepEqual(provider, {
    id: 'google',
    displayName: 'Google',
    enabled: true,
  });
  assert.equal(Object.prototype.hasOwnProperty.call(provider ?? {}, 'clientId'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(provider ?? {}, 'clientSecretEncrypted'), false);
});

test('public bootstrap provider hides disabled or unready providers', () => {
  assert.equal(publicBootstrapProviderFromConfig(providerRow({ status: SocialIdentityProviderStatus.INACTIVE })), null);
  assert.equal(publicBootstrapProviderFromConfig(providerRow({ showOnLogin: false })), null);
  assert.equal(publicBootstrapProviderFromConfig(providerRow({ lastSuccessfulTestAt: null })), null);
});

test('public bootstrap provider does not require admin checklist metadata after a successful technical test', () => {
  const provider = publicBootstrapProviderFromConfig(providerRow({ providerMetadata: {} }));

  assert.deepEqual(provider, {
    id: 'google',
    displayName: 'Google',
    enabled: true,
  });
});
