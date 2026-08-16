import 'dotenv/config';
import { prisma } from '../lib/db.js';
import { createClient } from '../modules/admin/admin.service.js';
import { AuthClientType } from '@prisma/client';
import fs from 'fs';

// Stage 2: idempotent registration of the three admin-frontend OAuth
// clients (authorization-code + PKCE). Client secrets are generated once,
// written directly into each frontend's env file, and never printed to
// stdout/logs. Safe to re-run: if a client with the given slug already
// exists, its secret is NOT rotated (existing secret stays valid) — only
// missing clients are created.

const CLIENTS: Array<{
  name: string;
  slug: string;
  audience: string;
  redirectUri: string;
  envFile: string;
  clientIdVar: string;
  clientSecretVar: string;
}> = [
  {
    name: 'BPA Admin (web)',
    slug: 'bpa-admin-web',
    audience: 'bpa-admin',
    redirectUri: 'https://admin.bangladeshpetassociation.com/api/auth/callback/central-auth',
    envFile: '/srv/config/bpa/admin.env',
    clientIdVar: 'CENTRAL_AUTH_CLIENT_ID',
    clientSecretVar: 'CENTRAL_AUTH_CLIENT_SECRET',
  },
  {
    name: 'WPA Gateway Admin (web)',
    slug: 'wpa-gateway-admin-web',
    audience: 'wpa-gateway-admin',
    redirectUri: 'https://admin.worldpetsassociation.com/api/auth/callback/central-auth',
    envFile: '/srv/config/wpa/admin.env',
    clientIdVar: 'CENTRAL_AUTH_CLIENT_ID',
    clientSecretVar: 'CENTRAL_AUTH_CLIENT_SECRET',
  },
  {
    name: 'WPA Central Auth Admin (web)',
    slug: 'wpa-auth-admin-web',
    audience: 'wpa-auth-admin',
    redirectUri: 'https://auth-admin.worldpetsassociation.com/api/auth/callback/central-auth',
    envFile: '/srv/config/wpa/auth-admin.env',
    clientIdVar: 'CENTRAL_AUTH_CLIENT_ID',
    clientSecretVar: 'CENTRAL_AUTH_CLIENT_SECRET',
  },
];

function upsertEnvVar(envFile: string, key: string, value: string) {
  let content = fs.readFileSync(envFile, 'utf8');
  const re = new RegExp(`^${key}=.*$`, 'm');
  if (re.test(content)) {
    content = content.replace(re, `${key}=${value}`);
  } else {
    if (!content.endsWith('\n')) content += '\n';
    content += `${key}=${value}\n`;
  }
  fs.writeFileSync(envFile, content, { mode: 0o600 });
  fs.chmodSync(envFile, 0o600);
}

async function main() {
  const results: Array<{ slug: string; status: 'created' | 'already_existed'; clientId: string; audience: string; redirectUri: string }> = [];

  for (const c of CLIENTS) {
    const existing = await prisma.authClient.findUnique({ where: { slug: c.slug } });
    if (existing) {
      results.push({ slug: c.slug, status: 'already_existed', clientId: existing.clientId, audience: existing.audience ?? '(unset)', redirectUri: c.redirectUri });
      // Ensure redirect URI / audience are still correct even if the client
      // already existed (idempotent config repair, never touches the secret).
      await prisma.authClient.update({
        where: { id: existing.id },
        data: { audience: c.audience, redirectUris: [c.redirectUri] },
      });
      continue;
    }

    const { client, clientSecret } = await createClient({
      name: c.name,
      slug: c.slug,
      type: AuthClientType.FIRST_PARTY_APP,
      redirectUris: [c.redirectUri],
      allowedScopes: ['openid', 'profile'],
    });
    await prisma.authClient.update({ where: { id: client.id }, data: { audience: c.audience } });

    // Write client id + secret directly into the target frontend's env
    // file. Never printed, logged, or returned from this script.
    if (!clientSecret) {
      throw new Error(`Expected a client secret for ${c.slug}.`);
    }
    upsertEnvVar(c.envFile, c.clientIdVar, client.clientId);
    upsertEnvVar(c.envFile, c.clientSecretVar, clientSecret);

    results.push({ slug: c.slug, status: 'created', clientId: client.clientId, audience: c.audience, redirectUri: c.redirectUri });
  }

  console.log(JSON.stringify({ results }, null, 2));
}

main().finally(() => prisma.$disconnect());
