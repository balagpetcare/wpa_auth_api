import test from 'node:test';
import assert from 'node:assert/strict';
import { signAccessToken, verifyAccessToken, signRefreshToken, verifyRefreshToken, getAllowedAudiences } from './tokens.js';
import { config } from '../config/index.js';

test('access tokens preserve the optional sid claim', () => {
  const token = signAccessToken({
    sub: 'user-123',
    email: 'owner@example.com',
    username: 'owner_user',
    roles: ['USER'],
    sid: 'sess_abc123',
  });

  const payload = verifyAccessToken(token);

  assert.equal(payload.sub, 'user-123');
  assert.equal(payload.sid, 'sess_abc123');
  assert.deepEqual(payload.roles, ['USER']);
});

test('access tokens signed with the client-supplied audience verify successfully when that audience is in the allowed list', () => {
  // getAllowedAudiences() always includes config.ACCESS_TOKEN_AUDIENCE
  // itself, so signing/verifying with that value round-trips regardless of
  // what ADDITIONAL_JWT_AUDIENCES is set to in this environment.
  const allowed = getAllowedAudiences();
  assert.ok(allowed.includes(config.ACCESS_TOKEN_AUDIENCE));

  const token = signAccessToken(
    { sub: 'user-456', email: null, username: null, roles: [] },
    config.ACCESS_TOKEN_AUDIENCE,
  );

  const payload = verifyAccessToken(token);
  assert.equal(payload.sub, 'user-456');
});

test('refresh tokens signed with a per-client audience verify successfully', () => {
  const token = signRefreshToken('user-789', config.ACCESS_TOKEN_AUDIENCE);
  const payload = verifyRefreshToken(token);
  assert.equal(payload.sub, 'user-789');
});

test('tokens signed with an audience outside the allowed list fail verification', () => {
  const token = signAccessToken(
    { sub: 'user-999', email: null, username: null, roles: [] },
    'some-unregistered-audience',
  );

  assert.throws(() => verifyAccessToken(token));
});
