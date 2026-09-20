import 'dotenv/config';
import crypto from 'crypto';
import { AuthClientStatus, AuthClientType, OidcIdTokenSigningAlg } from '@prisma/client';
import { prisma } from '../lib/db.js';
import {
  buildCommunityPetClinicClientConfig,
  publicBootstrapSummary,
} from './communityPetClinicClientConfig.js';

async function main() {
  const config = buildCommunityPetClinicClientConfig(process.env);
  const clientSecretHash = crypto.createHash('sha256').update(config.clientSecret).digest('hex');
  const existing = await prisma.authClient.findUnique({ where: { slug: config.slug } });
  const client = await prisma.authClient.upsert({
    where: { slug: config.slug },
    create: {
      name: config.name,
      slug: config.slug,
      type: AuthClientType.FIRST_PARTY_APP,
      clientId: config.clientId,
      clientSecretHash,
      oidcIdTokenSigningAlg: OidcIdTokenSigningAlg.RS256,
      allowedOrigins: [...config.allowedOrigins],
      redirectUris: [...config.redirectUris],
      postLogoutRedirectUris: [...config.postLogoutRedirectUris],
      allowedScopes: [...config.allowedScopes],
      status: AuthClientStatus.ACTIVE,
      audience: config.audience,
      allowedAuthMethods: [],
      accessTokenTtlSeconds: null,
      refreshTokenTtlSeconds: null,
      requiredProfileFields: [],
      registrationOpen: true,
    },
    update: {
      name: config.name,
      type: AuthClientType.FIRST_PARTY_APP,
      clientId: config.clientId,
      allowedOrigins: [...config.allowedOrigins],
      redirectUris: [...config.redirectUris],
      postLogoutRedirectUris: [...config.postLogoutRedirectUris],
      allowedScopes: [...config.allowedScopes],
      status: AuthClientStatus.ACTIVE,
      audience: config.audience,
      allowedAuthMethods: [],
      accessTokenTtlSeconds: null,
      refreshTokenTtlSeconds: null,
      requiredProfileFields: [],
      registrationOpen: true,
      ...(existing && process.env.ROTATE_CPC_CLIENT_SECRET === 'true' ? { clientSecretHash } : {}),
    },
  });
  console.log(JSON.stringify({ ...publicBootstrapSummary(config), result: existing ? 'updated' : 'created' }));
}

main()
  .catch((error: unknown) => {
    console.error('Failed to bootstrap Community Pet Clinic OAuth client:', error instanceof Error ? error.message : 'bootstrap failed');
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
