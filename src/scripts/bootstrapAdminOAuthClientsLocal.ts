import 'dotenv/config';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { prisma } from '../lib/db.js';
import { createClient } from '../modules/admin/admin.service.js';
import { AuthClientType } from '@prisma/client';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Local-dev counterpart to bootstrapAdminOAuthClients.ts. Registers the same
// admin-frontend OAuth clients but with http://localhost redirect URIs, and
// writes client id/secret into each admin's own .env.local (relative repo
// paths on this machine) instead of the production /srv/config layout.
// Idempotent and secret-preserving in the same way as the production script:
// re-running never rotates an existing client's secret, it only repairs the
// redirect URI / audience and creates clients that don't exist yet.
// Client id/secret are written to files only, never printed to stdout/logs.

// Every OAuth /authorize + credential-login request is made via the
// browser's fetch() from wpa_auth_web's own origin (not the admin panel's
// origin — the admin panel only ever navigates the top-level window there),
// so `allowedOrigins` must include wpa_auth_web's origin, not the admin
// panel's. See requireActiveClient()/resolveClient() in
// src/modules/oauth/oauth.service.ts and src/modules/auth/auth.service.ts.
const LOCAL_AUTH_WEB_ORIGIN = 'http://localhost:5011';

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
    name: 'BPA Admin (local)',
    slug: 'bpa-admin-web-local',
    audience: 'bpa-admin',
    redirectUri: 'http://localhost:3001/api/auth/callback/central-auth',
    envFile: path.resolve(__dirname, '../../../../../bpa_main/bpa_admin/.env.local'),
    clientIdVar: 'CENTRAL_AUTH_CLIENT_ID',
    clientSecretVar: 'CENTRAL_AUTH_CLIENT_SECRET',
  },
  {
    name: 'WPA Gateway Admin (local)',
    slug: 'wpa-gateway-admin-web-local',
    audience: 'wpa-gateway-admin',
    redirectUri: 'http://localhost:3002/api/auth/callback/central-auth',
    envFile: path.resolve(__dirname, '../../../../wpa_gateway/wpa_gateway_admin/.env.local'),
    clientIdVar: 'CENTRAL_AUTH_CLIENT_ID',
    clientSecretVar: 'CENTRAL_AUTH_CLIENT_SECRET',
  },
  {
    name: 'WPA Central Auth Admin (local)',
    slug: 'wpa-auth-admin-web-local',
    audience: 'wpa-auth-admin',
    redirectUri: 'http://localhost:5012/api/auth/callback/central-auth',
    envFile: path.resolve(__dirname, '../../../wpa_auth_admin/.env.local'),
    clientIdVar: 'CENTRAL_AUTH_CLIENT_ID',
    clientSecretVar: 'CENTRAL_AUTH_CLIENT_SECRET',
  },
];

function upsertEnvVar(envFile: string, key: string, value: string) {
  let content = fs.existsSync(envFile) ? fs.readFileSync(envFile, 'utf8') : '';
  const re = new RegExp(`^${key}=.*$`, 'm');
  if (re.test(content)) {
    content = content.replace(re, `${key}=${value}`);
  } else {
    if (content.length && !content.endsWith('\n')) content += '\n';
    content += `${key}=${value}\n`;
  }
  fs.writeFileSync(envFile, content);
}

async function main() {
  const results: Array<{ slug: string; status: 'created' | 'already_existed'; audience: string; redirectUri: string; envFile: string }> = [];

  for (const c of CLIENTS) {
    const existing = await prisma.authClient.findUnique({ where: { slug: c.slug } });
    if (existing) {
      results.push({ slug: c.slug, status: 'already_existed', audience: c.audience, redirectUri: c.redirectUri, envFile: c.envFile });
      await prisma.authClient.update({
        where: { id: existing.id },
        data: { audience: c.audience, redirectUris: [c.redirectUri], allowedOrigins: [LOCAL_AUTH_WEB_ORIGIN] },
      });
      continue;
    }

    const { client, clientSecret } = await createClient({
      name: c.name,
      slug: c.slug,
      type: AuthClientType.FIRST_PARTY_APP,
      redirectUris: [c.redirectUri],
      allowedOrigins: [LOCAL_AUTH_WEB_ORIGIN],
      allowedScopes: ['openid', 'profile'],
    });
    await prisma.authClient.update({ where: { id: client.id }, data: { audience: c.audience } });

    upsertEnvVar(c.envFile, c.clientIdVar, client.clientId);
    upsertEnvVar(c.envFile, c.clientSecretVar, clientSecret);

    results.push({ slug: c.slug, status: 'created', audience: c.audience, redirectUri: c.redirectUri, envFile: c.envFile });
  }

  console.log(JSON.stringify({ results }, null, 2));
}

main().finally(() => prisma.$disconnect());
