import test from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import type { Request } from 'express';
import { OAuthProvider } from '@prisma/client';
import { completeSocialAuthorizationContinuation } from './social.routes.js';
import type { SocialAuthorizationTransaction, SocialCallbackResult } from './social.service.js';
import { config } from '../../config/index.js';

function fakeReq(): Request {
  return {
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    headers: {},
  } as unknown as Request;
}

function tx(provider: OAuthProvider): SocialAuthorizationTransaction {
  return {
    mode: 'oauth',
    provider,
    clientId: 'bpa-web-client',
    clientDbId: 'client-db-id',
    redirectUri: 'https://bangladeshpetassociation.com/api/auth/central-auth/callback',
    scopes: ['openid', 'profile', 'email'],
    state: 'original-client-state',
    responseType: 'code',
    codeChallenge: 'S256ChallengeValue',
    codeChallengeMethod: 'S256',
    nonce: 'oidc-nonce',
    createdAt: new Date().toISOString(),
  };
}

function authenticatedResult(provider: OAuthProvider): SocialCallbackResult {
  return {
    kind: 'AUTHENTICATED',
    provider,
    user: {
      id: 'user-1',
      email: 'user@example.com',
      displayName: 'User One',
      avatarUrl: null,
      roles: ['USER'],
    },
  };
}

for (const provider of [OAuthProvider.GOOGLE, OAuthProvider.FACEBOOK, OAuthProvider.INSTAGRAM, OAuthProvider.X]) {
  test(`${provider} successful OAuth-mode social callback redirects with authorization code and original client state`, async () => {
    const calls: Array<Record<string, unknown>> = [];
    const result = await completeSocialAuthorizationContinuation({
      result: authenticatedResult(provider),
      statePayload: { provider, authTransactionId: `tx-${provider}` },
      req: fakeReq(),
      consumeTransaction: async (id) => {
        assert.equal(id, `tx-${provider}`);
        return tx(provider);
      },
      createAuthorizationCodeFn: async (input) => {
        calls.push(input as unknown as Record<string, unknown>);
        return { code: `code-${provider}`, state: input.state };
      },
    });

    assert.equal(result.kind, 'REDIRECT');
    assert.equal(
      result.location,
      `https://bangladeshpetassociation.com/api/auth/central-auth/callback?code=code-${provider}&state=original-client-state`,
    );
    assert.equal(calls.length, 1);
    assert.equal(calls[0].clientId, 'bpa-web-client');
    assert.equal(calls[0].redirectUri, 'https://bangladeshpetassociation.com/api/auth/central-auth/callback');
    assert.deepEqual(calls[0].scopes, ['openid', 'profile', 'email']);
    assert.equal(calls[0].codeChallenge, 'S256ChallengeValue');
    assert.equal(calls[0].codeChallengeMethod, 'S256');
    assert.equal(calls[0].nonce, 'oidc-nonce');
    assert.equal(calls[0].state, 'original-client-state');
    assert.doesNotMatch(result.location, /accessToken|refreshToken|provider.*token/i);
  });
}

test('social callback ignores redirect tampering and uses only the stored transaction redirect URI', async () => {
  const result = await completeSocialAuthorizationContinuation({
    result: authenticatedResult(OAuthProvider.GOOGLE),
    statePayload: { provider: OAuthProvider.GOOGLE, authTransactionId: 'tx-google' },
    req: {
      ...fakeReq(),
      query: { redirect_uri: 'https://attacker.example/callback' },
    } as unknown as Request,
    consumeTransaction: async () => tx(OAuthProvider.GOOGLE),
    createAuthorizationCodeFn: async (input) => ({ code: 'safe-code', state: input.state }),
  });

  assert.equal(result.kind, 'REDIRECT');
  assert.equal(
    result.location,
    'https://bangladeshpetassociation.com/api/auth/central-auth/callback?code=safe-code&state=original-client-state',
  );
  assert.doesNotMatch(result.location, /attacker\.example/);
});

test('X OAuth-mode provider state remains compact and does not carry client context or provider PKCE verifier', () => {
  const providerState = jwt.sign({
    provider: 'X',
    purpose: 'SOCIAL_LOGIN',
    nonce: 'short-server-reference',
    authTransactionId: 'short-server-reference',
    authMode: 'oauth',
    linkUserId: null,
  }, config.JWT_ACCESS_SECRET, { expiresIn: '10m' });
  const decoded = jwt.decode(providerState) as Record<string, unknown>;

  assert.ok(providerState.length < 500, `state length ${providerState.length} must stay below X limit`);
  assert.ok(providerState.length < 480, `state length ${providerState.length} must keep safety margin`);
  assert.equal(Object.prototype.hasOwnProperty.call(decoded, 'codeVerifier'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(decoded, 'redirectContext'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(decoded, 'audience'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(decoded, 'clientDbId'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(decoded, 'redirect_uri'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(decoded, 'code_challenge'), false);
});

test('expired social authorization transaction cannot be resumed and returns no tokens', async () => {
  const result = await completeSocialAuthorizationContinuation({
    result: authenticatedResult(OAuthProvider.GOOGLE),
    statePayload: { provider: OAuthProvider.GOOGLE, authTransactionId: 'expired-tx' },
    req: fakeReq(),
    consumeTransaction: async () => null,
    createAuthorizationCodeFn: async () => {
      throw new Error('authorization code must not be created for expired transactions');
    },
  });

  assert.equal(result.kind, 'ERROR');
  assert.equal(result.status, 400);
  assert.equal(result.body.code, 'INVALID_STATE');
  assert.doesNotMatch(JSON.stringify(result.body), /accessToken|refreshToken|provider.*token/i);
});

test('consumed social authorization transaction cannot be replayed', async () => {
  let consumed = false;
  const consumeTransaction = async () => {
    if (consumed) return null;
    consumed = true;
    return tx(OAuthProvider.FACEBOOK);
  };

  const first = await completeSocialAuthorizationContinuation({
    result: authenticatedResult(OAuthProvider.FACEBOOK),
    statePayload: { provider: OAuthProvider.FACEBOOK, authTransactionId: 'replay-tx' },
    req: fakeReq(),
    consumeTransaction,
    createAuthorizationCodeFn: async (input) => ({ code: 'first-code', state: input.state }),
  });
  const second = await completeSocialAuthorizationContinuation({
    result: authenticatedResult(OAuthProvider.FACEBOOK),
    statePayload: { provider: OAuthProvider.FACEBOOK, authTransactionId: 'replay-tx' },
    req: fakeReq(),
    consumeTransaction,
    createAuthorizationCodeFn: async () => {
      throw new Error('authorization code must not be created for replayed transactions');
    },
  });

  assert.equal(first.kind, 'REDIRECT');
  assert.equal(second.kind, 'ERROR');
  assert.equal(second.status, 400);
});

test('provider mismatch cannot consume another provider transaction', async () => {
  const result = await completeSocialAuthorizationContinuation({
    result: authenticatedResult(OAuthProvider.INSTAGRAM),
    statePayload: { provider: OAuthProvider.INSTAGRAM, authTransactionId: 'tx-provider-mismatch' },
    req: fakeReq(),
    consumeTransaction: async () => tx(OAuthProvider.X),
    createAuthorizationCodeFn: async () => {
      throw new Error('authorization code must not be created for provider mismatch');
    },
  });

  assert.equal(result.kind, 'ERROR');
  assert.equal(result.status, 400);
  assert.equal(result.body.code, 'INVALID_STATE');
  assert.doesNotMatch(JSON.stringify(result.body), /accessToken|refreshToken|provider.*token/i);
});

test('OAuth-mode EMAIL_REQUIRED result fails safely without issuing browser tokens', async () => {
  const result = await completeSocialAuthorizationContinuation({
    result: {
      kind: 'EMAIL_REQUIRED',
      provider: OAuthProvider.INSTAGRAM,
      completionToken: 'email-completion-token',
      message: 'Email required',
    },
    statePayload: { provider: OAuthProvider.INSTAGRAM, authTransactionId: 'tx-email-required' },
    req: fakeReq(),
    consumeTransaction: async () => tx(OAuthProvider.INSTAGRAM),
    createAuthorizationCodeFn: async () => {
      throw new Error('authorization code must not be created without an authenticated WPA user');
    },
  });

  assert.equal(result.kind, 'ERROR');
  assert.equal(result.status, 400);
  assert.equal(result.body.code, 'AUTHORIZATION_CONTINUATION_FAILED');
  assert.doesNotMatch(JSON.stringify(result.body), /accessToken|refreshToken|provider.*token/i);
});

test('standalone social login remains explicit JSON mode when no authorization transaction exists', async () => {
  const result = await completeSocialAuthorizationContinuation({
    result: {
      kind: 'LOGIN',
      accessToken: 'standalone-access-token',
      refreshToken: 'standalone-refresh-token',
      expiresIn: 3600,
      user: {
        id: 'user-1',
        email: 'user@example.com',
        displayName: 'User One',
        avatarUrl: null,
        roles: ['USER'],
      },
    },
    statePayload: {},
    req: fakeReq(),
    consumeTransaction: async () => {
      throw new Error('standalone mode must not consume an authorization transaction');
    },
  });

  assert.deepEqual(result, { kind: 'NONE' });
});
