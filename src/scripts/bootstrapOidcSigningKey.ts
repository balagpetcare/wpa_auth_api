import { generateKeyPairSync } from 'crypto';
import { prisma } from '../lib/db.js';
import { config } from '../config/index.js';
import { encryptCredentialPayload } from '../lib/credentialEncryption.js';
import { getCurrentSigningKeyMaterial } from '../lib/signingKeys.js';

async function main() {
  const existing = await getCurrentSigningKeyMaterial();
  if (existing) {
    console.log(`OIDC signing key already configured: kid=${existing.kid}`);
    return;
  }

  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const privateKeyEncrypted = encryptCredentialPayload({ privateKey });

  await prisma.oidcSigningKey.upsert({
    where: { kid: config.JWT_KEY_ID },
    create: {
      kid: config.JWT_KEY_ID,
      publicKey,
      privateKeyEncrypted,
      algorithm: 'RS256',
      active: true,
    },
    update: {
      publicKey,
      privateKeyEncrypted,
      algorithm: 'RS256',
      active: true,
      retiredAt: null,
    },
  });

  console.log(`OIDC signing key bootstrapped: kid=${config.JWT_KEY_ID}`);
}

main()
  .catch((error) => {
    console.error('Failed to bootstrap OIDC signing key:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
