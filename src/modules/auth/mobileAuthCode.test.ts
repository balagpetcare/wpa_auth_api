import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { verifyPkceS256, hashAuthCode } from './mobileAuthCode.service.js';

function makeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url'); // 43 chars
}

function challengeFor(verifier: string): string {
  return crypto.createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

test('PKCE S256: correct verifier matches its challenge', () => {
  const verifier = makeVerifier();
  assert.equal(verifyPkceS256(verifier, challengeFor(verifier)), true);
});

test('PKCE S256: wrong verifier is rejected', () => {
  const verifier = makeVerifier();
  const other = makeVerifier();
  assert.equal(verifyPkceS256(other, challengeFor(verifier)), false);
});

test('PKCE S256: too-short verifier is rejected even if hash would match', () => {
  const short = 'abc';
  assert.equal(verifyPkceS256(short, challengeFor(short)), false);
});

test('PKCE S256: over-long verifier (>128 chars) is rejected', () => {
  const long = 'a'.repeat(129);
  assert.equal(verifyPkceS256(long, challengeFor(long)), false);
});

test('PKCE S256: empty challenge never matches', () => {
  assert.equal(verifyPkceS256(makeVerifier(), ''), false);
});

test('auth code hashing is deterministic and never the raw code', () => {
  const code = crypto.randomBytes(32).toString('base64url');
  const h = hashAuthCode(code);
  assert.equal(h, hashAuthCode(code));
  assert.notEqual(h, code);
  assert.match(h, /^[0-9a-f]{64}$/);
});
