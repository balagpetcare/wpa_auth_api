import crypto from 'crypto';
import { prisma } from '../lib/db.js';
import { AuthClientStatus, AuthClientType, OidcIdTokenSigningAlg } from '@prisma/client';

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function splitCsv(name: string, fallback: string[]): string[] {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  return raw.split(',').map((value) => value.trim()).filter(Boolean);
}

async function main() {
  const clientId = process.env.BPA_WEB_CENTRAL_AUTH_CLIENT_ID?.trim() || 'bpa-web';
  const clientSecret = requiredEnv('BPA_WEB_CENTRAL_AUTH_CLIENT_SECRET');
  const redirectUris = splitCsv('BPA_WEB_CENTRAL_AUTH_REDIRECT_URIS', [
    'https://api.bangladeshpetassociation.com/api/v1/auth/central-auth/callback',
  ]);
  const allowedOrigins = splitCsv('BPA_WEB_CENTRAL_AUTH_ALLOWED_ORIGINS', [
    'https://bangladeshpetassociation.com',
  ]);
  const clientSecretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');

  const client = await prisma.authClient.upsert({
    where: { slug: 'bpa-web' },
    create: {
      name: 'Bangladesh Pet Association',
      slug: 'bpa-web',
      type: AuthClientType.FIRST_PARTY_APP,
      clientId,
      clientSecretHash,
      oidcIdTokenSigningAlg: OidcIdTokenSigningAlg.RS256,
      allowedOrigins,
      redirectUris,
      allowedScopes: ['openid', 'profile', 'email'],
      status: AuthClientStatus.ACTIVE,
      audience: 'bpa-web',
      allowedAuthMethods: [],
      accessTokenTtlSeconds: null,
      refreshTokenTtlSeconds: null,
      requiredProfileFields: [],
      registrationOpen: true,
    },
    update: {
      name: 'Bangladesh Pet Association',
      type: AuthClientType.FIRST_PARTY_APP,
      clientId,
      clientSecretHash,
      oidcIdTokenSigningAlg: OidcIdTokenSigningAlg.RS256,
      allowedOrigins,
      redirectUris,
      allowedScopes: ['openid', 'profile', 'email'],
      status: AuthClientStatus.ACTIVE,
      audience: 'bpa-web',
      allowedAuthMethods: [],
      accessTokenTtlSeconds: null,
      refreshTokenTtlSeconds: null,
      requiredProfileFields: [],
      registrationOpen: true,
    },
  });

  await prisma.clientBranding.upsert({
    where: { clientId: client.id },
    create: {
      clientId: client.id,
      senderName: 'Bangladesh Pet Association',
      brandColor: '#0f3a7d',
      accentColor: '#1a5ba8',
      websiteUrl: 'https://bangladeshpetassociation.com',
      privacyUrl: 'https://bangladeshpetassociation.com/privacy-policy',
      termsUrl: 'https://bangladeshpetassociation.com/terms',
      isActive: true,
    },
    update: {
      senderName: 'Bangladesh Pet Association',
      brandColor: '#0f3a7d',
      accentColor: '#1a5ba8',
      websiteUrl: 'https://bangladeshpetassociation.com',
      privacyUrl: 'https://bangladeshpetassociation.com/privacy-policy',
      termsUrl: 'https://bangladeshpetassociation.com/terms',
      isActive: true,
    },
  });

  console.log(`BPA Web client bootstrapped: slug=${client.slug}, clientId=${client.clientId}`);
}

main()
  .catch((error) => {
    console.error('Failed to bootstrap BPA Web Central Auth client:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
