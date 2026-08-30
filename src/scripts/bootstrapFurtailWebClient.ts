import crypto from 'crypto';
import { prisma } from '../lib/db.js';
import { AuthClientStatus, AuthClientType } from '@prisma/client';

async function main() {
  const clientSecret = process.env.FURTAIL_WEB_CENTRAL_AUTH_CLIENT_SECRET?.trim() || 'furtail-secret';
  const clientSecretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');

  const client = await prisma.authClient.upsert({
    where: { slug: 'furtail-web' },
    create: {
      name: 'Furtail Web',
      slug: 'furtail-web',
      type: AuthClientType.FIRST_PARTY_APP,
      clientId: 'furtail-web',
      clientSecretHash,
      allowedOrigins: [
        'http://localhost:5011',
        'http://localhost:7400'
      ],
      redirectUris: [
        'http://localhost:7400/api/auth/callback'
      ],
      allowedScopes: ['openid', 'profile', 'email'],
      status: AuthClientStatus.ACTIVE,
      audience: 'furtail',
      allowedAuthMethods: [],
      accessTokenTtlSeconds: null,
      refreshTokenTtlSeconds: null,
      requiredProfileFields: [],
      registrationOpen: true,
    },
    update: {
      name: 'Furtail Web',
      type: AuthClientType.FIRST_PARTY_APP,
      clientId: 'furtail-web',
      clientSecretHash,
      allowedOrigins: [
        'http://localhost:5011',
        'http://localhost:7400'
      ],
      redirectUris: [
        'http://localhost:7400/api/auth/callback'
      ],
      allowedScopes: ['openid', 'profile', 'email'],
      status: AuthClientStatus.ACTIVE,
      audience: 'furtail',
    },
  });

  await prisma.clientBranding.upsert({
    where: { clientId: client.id },
    create: {
      clientId: client.id,
      senderName: 'Furtail Web',
      brandColor: '#4f46e5',
      accentColor: '#4338ca',
      websiteUrl: 'http://localhost:7400',
      isActive: true,
    },
    update: {
      senderName: 'Furtail Web',
      brandColor: '#4f46e5',
      accentColor: '#4338ca',
      websiteUrl: 'http://localhost:7400',
      isActive: true,
    },
  });

  console.log(`Furtail Web client bootstrapped: slug=${client.slug}, clientId=${client.clientId}`);
}

main()
  .catch((error) => {
    console.error('Failed to bootstrap Furtail Web client:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
