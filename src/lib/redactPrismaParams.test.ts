import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactPrismaParams } from './redactPrismaParams.js';

test('redacts a scrypt/bcrypt password hash to a length-only secret marker', () => {
  const out = redactPrismaParams('["a@b.com","scrypt$1$abcd1234$deadbeefdeadbeefdeadbeefdeadbeef",7]');
  assert.ok(!out.includes('scrypt$1$abcd'));
  assert.ok(!out.includes('deadbeef'));
  assert.match(out, /redacted:secret/);
  assert.ok(out.includes('7'), 'plain numbers are kept for query diagnostics');
});

test('redacts long hex tokens and JWT-shaped strings', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdef';
  const hex = 'a'.repeat(64);
  const out = redactPrismaParams(JSON.stringify([jwt, hex]));
  assert.ok(!out.includes(jwt));
  assert.ok(!out.includes(hex));
});

test('keeps short non-secret strings length-only, never verbatim', () => {
  const out = redactPrismaParams('["ACTIVE","furtail-admin"]');
  assert.ok(!out.includes('furtail-admin'));
  assert.match(out, /redacted:string len=13/);
});

test('handles unparseable input without throwing', () => {
  assert.equal(redactPrismaParams('not json'), '[unpar;redacted]');
});
