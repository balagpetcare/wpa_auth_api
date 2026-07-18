// Pure unit tests for per-client reset/verify link routing (final hardening
// pass). No DB/Redis/config needed. Verifies the fix for the previously-
// reported bug where the reset email always pointed at the admin panel.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseClientUrlMap, appendToken, buildActionLink } from './resetLinkRouting.js';

const MAP = JSON.stringify({
  'furtail-mobile': 'furtail://reset-password',
  'bpa-mobile': 'bpa://reset-password',
});
const ADMIN_DEFAULT = 'https://admin.example.com/auth/user/reset-password';

test('known clientId routes to its app deep link', () => {
  const link = buildActionLink(MAP, 'furtail-mobile', 'tok123', ADMIN_DEFAULT);
  assert.equal(link, 'furtail://reset-password?token=tok123');
});

test('a different client keeps its own deep link', () => {
  const link = buildActionLink(MAP, 'bpa-mobile', 'tok123', ADMIN_DEFAULT);
  assert.equal(link, 'bpa://reset-password?token=tok123');
});

test('no clientId falls back to admin-panel default (admin flow unbroken)', () => {
  const link = buildActionLink(MAP, undefined, 'tok123', ADMIN_DEFAULT);
  assert.equal(link, 'https://admin.example.com/auth/user/reset-password?token=tok123');
});

test('unknown clientId falls back to admin-panel default', () => {
  const link = buildActionLink(MAP, 'some-web-client', 'tok123', ADMIN_DEFAULT);
  assert.equal(link, 'https://admin.example.com/auth/user/reset-password?token=tok123');
});

test('empty/malformed map degrades safely to default (never throws)', () => {
  assert.equal(buildActionLink('', 'furtail-mobile', 't', ADMIN_DEFAULT), `${ADMIN_DEFAULT}?token=t`);
  assert.equal(buildActionLink('{not json', 'furtail-mobile', 't', ADMIN_DEFAULT), `${ADMIN_DEFAULT}?token=t`);
  assert.equal(buildActionLink('[1,2,3]', 'furtail-mobile', 't', ADMIN_DEFAULT), `${ADMIN_DEFAULT}?token=t`);
});

test('appendToken respects an existing query string', () => {
  assert.equal(appendToken('furtail://reset?x=1', 'abc'), 'furtail://reset?x=1&token=abc');
});

test('token is url-encoded', () => {
  assert.equal(appendToken('https://a/b', 'a b/c'), 'https://a/b?token=a%20b%2Fc');
});

test('parseClientUrlMap ignores non-string / empty values', () => {
  const m = parseClientUrlMap(JSON.stringify({ a: 'x', b: '', c: 5, d: null }));
  assert.deepEqual(m, { a: 'x' });
});
