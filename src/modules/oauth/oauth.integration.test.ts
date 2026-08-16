import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { prisma } from '../../lib/db.js';
import { encryptCredentialPayload } from '../../lib/credentialEncryption.js';
import { buildOpenIdConfiguration } from '../../lib/oidc.js';
import { exchangeAuthorizationCode, startAuthorization } from './oauth.service.js';
import { signIdToken } from '../../lib/tokens.js';

function fakeReq() {
  return {
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    headers: {},
  } as any;
}

function unique(prefix: string) {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function makePkceVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function makePkceChallenge(verifier: string) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

async function cleanupClient(clientDbId: string) {
  await prisma.authorizationCode.deleteMany({ where: { clientId: clientDbId } });
  await prisma.refreshToken.deleteMany({ where: { clientId: clientDbId } });
  await prisma.loginSession.deleteMany({ where: { clientId: clientDbId } });
  await prisma.authClient.deleteMany({ where: { id: clientDbId } });
}

async function cleanupSigningKey(kid: string) {
  await prisma.oidcSigningKey.deleteMany({ where: { kid } });
}

async function cleanupUser(userId: string) {
  await prisma.authorizationCode.deleteMany({ where: { userId } });
  await prisma.refreshToken.deleteMany({ where: { userId } });
  await prisma.loginSession.deleteMany({ where: { userId } });
  await prisma.user.delete({ where: { id: userId } }).catch(() => undefined);
}

async function makeRsaSigningKey(kid: string) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  await prisma.oidcSigningKey.upsert({
    where: { kid },
    create: {
      kid,
      publicKey,
      privateKeyEncrypted: encryptCredentialPayload({ privateKey }),
      algorithm: 'RS256',
      active: true,
    },
    update: {
      publicKey,
      privateKeyEncrypted: encryptCredentialPayload({ privateKey }),
      algorithm: 'RS256',
      active: true,
      retiredAt: null,
    },
  });

  return { kid, publicKey, privateKey };
}

async function makeClient(input: {
  clientId: string;
  slug: string;
  type?: 'FIRST_PARTY_APP' | 'THIRD_PARTY_APP' | 'SERVICE';
  secret?: boolean;
  signingAlg?: 'HS256' | 'RS256' | null;
}) {
  const secret = input.secret === false ? null : crypto.randomBytes(32).toString('hex');
  const client = await prisma.authClient.create({
    data: {
      name: input.slug,
      slug: input.slug,
      type: input.type ?? 'FIRST_PARTY_APP',
      clientId: input.clientId,
      clientSecretHash: secret ? crypto.createHash('sha256').update(secret).digest('hex') : null,
      oidcIdTokenSigningAlg: input.signingAlg ?? null,
      allowedOrigins: secret ? ['https://example.com'] : [],
      redirectUris: secret ? ['https://example.com/api/auth/callback'] : ['https://example.com/callback'],
      allowedScopes: ['openid', 'profile', 'email'],
      status: 'ACTIVE',
    },
  });
  return { client, secret };
}

test('authorization code flow enforces PKCE, one-time use, exact redirect_uri, and RS256 id_token signing', async () => {
  const user = await prisma.user.create({
    data: {
      email: `${unique('oidc-user')}@example.com`,
      status: 'ACTIVE',
      emailVerifiedAt: new Date(),
    },
  });
  const signingKey = await makeRsaSigningKey(`oidc-test-key-${Date.now()}`);
  const { client, secret } = await makeClient({
    clientId: unique('oidc-client'),
    slug: unique('oidc-client'),
    secret: true,
    signingAlg: 'RS256',
  });

  const verifier = makePkceVerifier();
  const challenge = makePkceChallenge(verifier);
  const redirectUri = 'https://example.com/api/auth/callback';

  try {
    const auth = await startAuthorization({
      clientId: client.clientId,
      redirectUri,
      scopes: ['openid', 'profile', 'email'],
      state: 'state-123',
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
      nonce: 'nonce-123',
      userId: user.id,
      req: fakeReq(),
    });

    assert.equal(auth.requiresConsent, false);
    assert.ok(auth.code);
    assert.equal(auth.state, 'state-123');

    const issued = await prisma.authorizationCode.findUnique({ where: { codeHash: crypto.createHash('sha256').update(auth.code).digest('hex') } });
    assert.ok(issued);
    assert.equal(issued?.redirectUri, redirectUri);
    assert.equal(issued?.codeChallenge, challenge);
    assert.equal(issued?.usedAt, null);

    await assert.rejects(
      () => exchangeAuthorizationCode({
        code: auth.code,
        clientId: client.clientId,
        clientSecret: 'wrong-secret',
        redirectUri,
        codeVerifier: verifier,
        req: fakeReq(),
      }),
      (err: any) => err.code === 'INVALID_CLIENT',
    );

    const tokens = await exchangeAuthorizationCode({
      code: auth.code,
      clientId: client.clientId,
      clientSecret: secret ?? undefined,
      redirectUri,
      codeVerifier: verifier,
      req: fakeReq(),
    });

    assert.ok(tokens.id_token);
    const decoded = jwt.decode(tokens.id_token as string, { complete: true }) as { header?: { alg?: string; kid?: string } };
    assert.equal(decoded.header?.alg, 'RS256');
    assert.ok(decoded.header?.kid);
    assert.equal(jwt.verify(tokens.id_token as string, signingKey.publicKey, { algorithms: ['RS256'] }) !== undefined, true);

    await assert.rejects(
      () => exchangeAuthorizationCode({
        code: auth.code,
        clientId: client.clientId,
        clientSecret: secret ?? undefined,
        redirectUri,
        codeVerifier: verifier,
        req: fakeReq(),
      }),
      (err: any) => err.code === 'INVALID_GRANT',
    );

    const secondClient = await makeClient({
      clientId: unique('oidc-client-2'),
      slug: unique('oidc-client-2'),
      secret: true,
      signingAlg: 'RS256',
    });

    await assert.rejects(
      () => exchangeAuthorizationCode({
        code: auth.code,
        clientId: secondClient.client.clientId,
        clientSecret: secondClient.secret ?? undefined,
        redirectUri,
        codeVerifier: verifier,
        req: fakeReq(),
      }),
      (err: any) => err.code === 'INVALID_GRANT',
    );

    await cleanupClient(secondClient.client.id);
  } finally {
    await cleanupClient(client.id);
    await cleanupUser(user.id);
    await cleanupSigningKey(signingKey.kid);
  }
});

test('public native clients require PKCE and can exchange without a client secret', async () => {
  const user = await prisma.user.create({
    data: {
      email: `${unique('oidc-public-user')}@example.com`,
      status: 'ACTIVE',
      emailVerifiedAt: new Date(),
    },
  });
  const { client } = await makeClient({
    clientId: unique('oidc-public-client'),
    slug: unique('oidc-public-client'),
    secret: false,
    signingAlg: 'RS256',
  });

  try {
    await assert.rejects(
      () => startAuthorization({
        clientId: client.clientId,
        redirectUri: 'https://example.com/callback',
        scopes: ['openid', 'profile', 'email'],
        state: 'state-1',
        userId: user.id,
        req: fakeReq(),
      } as any),
      (err: any) => err.code === 'INVALID_REQUEST',
    );

    const verifier = makePkceVerifier();
    const auth = await startAuthorization({
      clientId: client.clientId,
      redirectUri: 'https://example.com/callback',
      scopes: ['profile', 'email'],
      state: 'state-2',
      codeChallenge: makePkceChallenge(verifier),
      codeChallengeMethod: 'S256',
      nonce: 'nonce-2',
      userId: user.id,
      req: fakeReq(),
    });

    if (!('code' in auth)) {
      throw new Error('Expected authorization code response.');
    }
    const tokens = await exchangeAuthorizationCode({
      code: auth.code,
      clientId: client.clientId,
      redirectUri: 'https://example.com/callback',
      codeVerifier: verifier,
      req: fakeReq(),
    });

    assert.ok(tokens.access_token);
    assert.ok(tokens.refresh_token);
  } finally {
    await cleanupClient(client.id);
    await cleanupUser(user.id);
  }
});

test('discovery metadata reflects absolute endpoints and supported algorithms', async () => {
  const { client } = await makeClient({
    clientId: unique('oidc-discovery-client'),
    slug: unique('oidc-discovery-client'),
    secret: true,
    signingAlg: 'RS256',
  });
  const { client: legacyClient } = await makeClient({
    clientId: unique('oidc-legacy-client'),
    slug: unique('oidc-legacy-client'),
    secret: true,
    signingAlg: null,
  });
  const key = await makeRsaSigningKey(`oidc-discovery-key-${Date.now()}`);

  try {
    const discovery = await buildOpenIdConfiguration();
    assert.equal(discovery.issuer, 'https://auth.worldpetsassociation.com');
    assert.match(discovery.authorization_endpoint, /^https:\/\/auth\.worldpetsassociation\.com\/api\/v1\/oauth\/authorize$/);
    assert.match(discovery.token_endpoint, /^https:\/\/auth\.worldpetsassociation\.com\/api\/v1\/oauth\/token$/);
    assert.deepEqual(new Set(discovery.id_token_signing_alg_values_supported), new Set(['HS256', 'RS256']));

    const token = await signIdToken({ iss: discovery.issuer, sub: 'sub-1', aud: client.clientId, iat: Math.floor(Date.now() / 1000) }, 60, 'RS256');
    const decoded = jwt.decode(token, { complete: true }) as { header?: { alg?: string; kid?: string } };
    assert.equal(decoded.header?.alg, 'RS256');
    assert.equal(decoded.header?.kid, key.kid);
  } finally {
    await cleanupClient(client.id);
    await cleanupClient(legacyClient.id);
    await cleanupSigningKey(key.kid);
  }
});
