import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildCommunityPetClinicClientConfig,
  COMMUNITY_PET_CLINIC_DEFAULTS,
  publicBootstrapSummary,
} from './communityPetClinicClientConfig.js';

test('builds the exact local CPC registration without wildcard origins', () => {
  const config = buildCommunityPetClinicClientConfig({ CPC_CENTRAL_AUTH_CLIENT_SECRET: 'fake-secret' });
  assert.deepEqual(config.redirectUris, COMMUNITY_PET_CLINIC_DEFAULTS.redirectUris);
  assert.deepEqual(config.postLogoutRedirectUris, COMMUNITY_PET_CLINIC_DEFAULTS.postLogoutRedirectUris);
  assert.deepEqual(config.allowedOrigins, ['http://localhost:3002']);
  assert.deepEqual(config.allowedScopes, ['openid', 'profile', 'email']);
  assert.equal(config.audience, 'community-pet-clinic');
  assert.ok(!config.allowedOrigins.includes('*'));
  assert.equal('clientSecret' in publicBootstrapSummary(config), false);
});

test('requires a secret and supports non-secret overrides', () => {
  assert.throws(() => buildCommunityPetClinicClientConfig({}), /CPC_CENTRAL_AUTH_CLIENT_SECRET/);
  const config = buildCommunityPetClinicClientConfig({
    CPC_CENTRAL_AUTH_CLIENT_SECRET: 'fake-secret',
    CPC_CENTRAL_AUTH_CLIENT_ID: 'custom-id',
    CPC_CENTRAL_AUTH_REDIRECT_URIS: 'http://localhost:7701/auth/callback,http://localhost:7702/auth/callback',
  });
  assert.equal(config.clientId, 'custom-id');
  assert.equal(config.redirectUris.length, 2);
});
