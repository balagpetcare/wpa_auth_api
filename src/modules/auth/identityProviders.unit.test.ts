// Unit tests for the JWKS-based id_token verification helper used by every
// OIDC-style adapter (google.ts, apple.ts, microsoft.ts, enterprise.ts).
// Runs a local key pair + an in-process HTTP server standing in for a
// provider's real JWKS endpoint (jose's createRemoteJWKSet just does an
// HTTP GET + parses a standard JWK Set), so signature/issuer/audience/
// expiry checks are exercised for real, without depending on Google/Apple/
// Microsoft's live endpoints or their real key material.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { verifyIdToken } from './identity-providers/jwksVerifier.js';

async function startJwksServer(jwk: Record<string, unknown>) {
  const server = http.createServer((_req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return { server, url: `http://127.0.0.1:${port}/jwks` };
}

test('jwksVerifier accepts a validly signed token matching iss/aud/exp', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const kid = 'test-key-1';
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  const { server, url } = await startJwksServer(publicJwk);

  try {
    const token = await new SignJWT({ email: 'user@example.com', email_verified: true })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer('https://issuer.example.com')
      .setAudience('test-client-id')
      .setSubject('subject-123')
      .setExpirationTime('10m')
      .sign(privateKey);

    const payload = await verifyIdToken(token, {
      jwksUri: url,
      issuer: 'https://issuer.example.com',
      audience: 'test-client-id',
    });
    assert.equal(payload.sub, 'subject-123');
    assert.equal(payload.email, 'user@example.com');
    assert.equal(payload.email_verified, true);
  } finally {
    server.close();
  }
});

test('jwksVerifier rejects a token with the wrong audience', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const kid = 'test-key-2';
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  const { server, url } = await startJwksServer(publicJwk);

  try {
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer('https://issuer.example.com')
      .setAudience('someone-elses-client-id')
      .setSubject('subject-123')
      .setExpirationTime('10m')
      .sign(privateKey);

    await assert.rejects(
      () => verifyIdToken(token, { jwksUri: url, issuer: 'https://issuer.example.com', audience: 'test-client-id' }),
      (err: any) => err.code === 'INVALID_PROVIDER_TOKEN',
    );
  } finally {
    server.close();
  }
});

test('jwksVerifier rejects an expired token', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const kid = 'test-key-3';
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  const { server, url } = await startJwksServer(publicJwk);

  try {
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer('https://issuer.example.com')
      .setAudience('test-client-id')
      .setSubject('subject-123')
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1800)
      .sign(privateKey);

    await assert.rejects(
      () => verifyIdToken(token, { jwksUri: url, issuer: 'https://issuer.example.com', audience: 'test-client-id' }),
      (err: any) => err.code === 'INVALID_PROVIDER_TOKEN',
    );
  } finally {
    server.close();
  }
});

test('jwksVerifier rejects a token signed by a different key (untrusted signer)', async () => {
  const legit = await generateKeyPair('RS256');
  const attacker = await generateKeyPair('RS256');
  const kid = 'test-key-4';
  // JWKS only publishes the LEGITIMATE public key.
  const publicJwk = { ...(await exportJWK(legit.publicKey)), kid, alg: 'RS256', use: 'sig' };
  const { server, url } = await startJwksServer(publicJwk);

  try {
    // Token is signed with the attacker's private key but claims the same kid.
    const forged = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer('https://issuer.example.com')
      .setAudience('test-client-id')
      .setSubject('victim-subject')
      .setExpirationTime('10m')
      .sign(attacker.privateKey);

    await assert.rejects(
      () => verifyIdToken(forged, { jwksUri: url, issuer: 'https://issuer.example.com', audience: 'test-client-id' }),
      (err: any) => err.code === 'INVALID_PROVIDER_TOKEN',
    );
  } finally {
    server.close();
  }
});
