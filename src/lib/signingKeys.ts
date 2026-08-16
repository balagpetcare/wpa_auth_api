import { createPublicKey } from 'crypto';
import { prisma } from './db.js';
import { config } from '../config/index.js';
import { decryptCredentialPayload } from './credentialEncryption.js';

export type SigningKeyRecord = {
  kid: string;
  publicKey: string;
  algorithm: string;
  active: boolean;
  createdAt: Date;
  retiredAt: Date | null;
};

function normalizePem(pem: string) {
  return pem.replace(/\\n/g, '\n');
}

function envKeyRecord(): SigningKeyRecord | null {
  if (!config.JWT_RSA_PRIVATE_KEY && !config.JWT_RSA_PUBLIC_KEY) return null;
  const publicKey = config.JWT_RSA_PUBLIC_KEY
    ? normalizePem(config.JWT_RSA_PUBLIC_KEY)
    : createPublicKey(normalizePem(config.JWT_RSA_PRIVATE_KEY as string)).export({ format: 'pem', type: 'spki' }).toString();
  return {
    kid: config.JWT_KEY_ID,
    publicKey,
    algorithm: 'RS256',
    active: true,
    createdAt: new Date(0),
    retiredAt: null,
  };
}

function parseJsonKeyRing(): SigningKeyRecord[] {
  if (!config.JWT_RSA_PUBLIC_KEYS_JSON) return [];
  try {
    const parsed = JSON.parse(config.JWT_RSA_PUBLIC_KEYS_JSON) as Array<Partial<SigningKeyRecord> & { publicKey?: string }>;
    return parsed
      .filter((key): key is SigningKeyRecord => !!key && typeof key.kid === 'string' && typeof key.publicKey === 'string')
      .map((key) => ({
        kid: key.kid,
        publicKey: normalizePem(key.publicKey),
        algorithm: key.algorithm ?? 'RS256',
        active: key.active !== false,
        createdAt: key.createdAt ? new Date(key.createdAt) : new Date(),
        retiredAt: key.retiredAt ? new Date(key.retiredAt) : null,
      }))
      .filter((key) => key.active);
  } catch {
    return [];
  }
}

export async function listActiveSigningKeys(): Promise<SigningKeyRecord[]> {
  const dbKeys = await prisma.oidcSigningKey.findMany({
    where: { active: true },
    orderBy: [{ createdAt: 'desc' }, { kid: 'desc' }],
      select: {
        kid: true,
        publicKey: true,
        algorithm: true,
        active: true,
        createdAt: true,
        retiredAt: true,
    },
  });

  const combined = [...dbKeys, ...parseJsonKeyRing()];
  const deduped = Array.from(new Map(combined.map((key) => [key.kid, key])).values());
  if (deduped.length > 0) return deduped;
  const fallback = envKeyRecord();
  return fallback ? [fallback] : [];
}

export async function getCurrentSigningKey() {
  const keys = await listActiveSigningKeys();
  return keys[0] ?? null;
}

export async function getCurrentSigningKeyMaterial(): Promise<{ kid: string; publicKey: string; privateKey: string; algorithm: string } | null> {
  const keyRows = await prisma.oidcSigningKey.findMany({
    where: { active: true },
    orderBy: [{ createdAt: 'desc' }, { kid: 'desc' }],
      select: {
        kid: true,
        publicKey: true,
        privateKeyEncrypted: true,
        algorithm: true,
      active: true,
      createdAt: true,
      retiredAt: true,
    },
  });

  for (const row of keyRows) {
    if (!row.privateKeyEncrypted || row.algorithm !== 'RS256') continue;
    try {
      const payload = decryptCredentialPayload(row.privateKeyEncrypted as any) as { privateKey?: string };
      if (!payload.privateKey) continue;
      return {
        kid: row.kid,
        publicKey: row.publicKey,
        privateKey: payload.privateKey.replace(/\\n/g, '\n'),
        algorithm: row.algorithm,
      };
    } catch {
      continue;
    }
  }

  if (config.JWT_RSA_PRIVATE_KEY) {
    const privateKey = config.JWT_RSA_PRIVATE_KEY.replace(/\\n/g, '\n');
    const publicKey = config.JWT_RSA_PUBLIC_KEY?.replace(/\\n/g, '\n') ?? createPublicKey(privateKey).export({ format: 'pem', type: 'spki' }).toString();
    return {
      kid: config.JWT_KEY_ID,
      publicKey,
      privateKey,
      algorithm: 'RS256',
    };
  }

  return null;
}

export async function exportJwks() {
  const keys = await listActiveSigningKeys();
  const jwks = keys.flatMap((key) => {
    try {
      const keyObject = createPublicKey(key.publicKey);
      if (keyObject.asymmetricKeyType !== 'rsa') return [];
      const jwk = keyObject.export({ format: 'jwk' }) as { kty: string; n: string; e: string };
      return [{
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        use: 'sig',
        alg: key.algorithm === 'RS256' ? 'RS256' : 'HS256',
        kid: key.kid,
      }];
    } catch {
      return [];
    }
  });

  if (jwks.length > 0) {
    return { keys: jwks };
  }

  if (config.JWT_RSA_PUBLIC_KEY) {
    const keyObject = createPublicKey(normalizePem(config.JWT_RSA_PUBLIC_KEY));
    const jwk = keyObject.export({ format: 'jwk' }) as { kty: string; n: string; e: string };
    return {
      keys: [{
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        use: 'sig',
        alg: 'RS256',
        kid: config.JWT_KEY_ID,
      }],
    };
  }

  return {
    keys: [{
      kty: 'oct',
      use: 'sig',
      alg: 'HS256',
      kid: config.JWT_KEY_ID,
      note: 'Symmetric key in use. Set RSA public keys for standards-based OIDC verification.',
    }],
  };
}
