/**
 * Targeted repair script: fixes the two root causes of the Central Auth
 * login/authorize failure without re-running the full seed.
 *
 * 1. Creates the `furtail-admin` OAuth client (missing — caused 401
 *    INVALID_CLIENT → login loop).
 * 2. Fixes empty `allowedScopes` on ALL existing clients (caused
 *    INVALID_SCOPE even for `openid`).
 *
 * Usage: npx tsx scripts/fix-oauth-clients.ts
 */
import crypto from 'crypto';
import { prisma } from '../src/lib/db.js';
import { AuthClientType, AuthClientStatus } from '@prisma/client';

const STANDARD_OIDC_SCOPES = ['openid', 'profile', 'email'];

async function main() {
  // ── 1. Create the furtail-admin client if missing ──
  const adminSlug = 'furtail-admin';
  const adminClientId = 'furtail-admin';
  const existing = await prisma.authClient.findUnique({ where: { slug: adminSlug } });

  if (!existing) {
    // Generate a client secret (the admin app's .env must set WPA_CLIENT_SECRET
    // to this value). In dev, a fixed secret is acceptable for local use.
    const devSecret = process.env.FURTAIL_ADMIN_CLIENT_SECRET || crypto.randomBytes(32).toString('base64url');
    const hash = crypto.createHash('sha256').update(devSecret).digest('hex');

    const created = await prisma.authClient.create({
      data: {
        name: 'Furtail Admin',
        slug: adminSlug,
        type: AuthClientType.FIRST_PARTY_APP,
        clientId: adminClientId,
        clientSecretHash: hash,
        status: AuthClientStatus.ACTIVE,
        allowedOrigins: ['http://localhost:7500', 'http://localhost:5011'],
        redirectUris: ['http://localhost:7500/api/auth/callback'],
        allowedScopes: STANDARD_OIDC_SCOPES,
        audience: 'furtail-admin',
        allowedAuthMethods: [],
      },
    });

    console.log('Created furtail-admin client:');
    console.log('  id            :', created.id);
    console.log('  clientId      :', created.clientId);
    console.log('  redirectUris  :', JSON.stringify(created.redirectUris));
    console.log('  allowedScopes :', JSON.stringify(created.allowedScopes));
    console.log('  audience      :', created.audience);
    console.log('  Client Secret :', devSecret);
    console.log('  [ACTION REQUIRED] Set WPA_CLIENT_SECRET=' + devSecret + ' in furtail_admin/.env');
  } else {
    // Update the existing client to fix redirect URIs + scopes
    await prisma.authClient.update({
      where: { id: existing.id },
      data: {
        clientId: adminClientId,
        status: AuthClientStatus.ACTIVE,
        redirectUris: ['http://localhost:7500/api/auth/callback'],
        allowedScopes: STANDARD_OIDC_SCOPES,
        audience: 'furtail-admin',
        allowedOrigins: ['http://localhost:7500', 'http://localhost:5011'],
      },
    });
    console.log('Updated existing furtail-admin client (fixed redirect URIs + scopes)');
  }

  // Also ensure furtail-web client has correct scopes if it exists
  const furtailWeb = await prisma.authClient.findUnique({ where: { slug: 'furtail-web' } });
  if (furtailWeb) {
    await prisma.authClient.update({
      where: { id: furtailWeb.id },
      data: {
        allowedScopes: STANDARD_OIDC_SCOPES,
        redirectUris: ['http://localhost:7400/api/auth/callback'],
      },
    });
    console.log('Updated furtail-web client (fixed scopes + redirect URIs)');
  }

  // ── 2. Fix empty allowedScopes on ALL clients ──
  const allClients = await prisma.authClient.findMany();
  let fixedCount = 0;
  for (const c of allClients) {
    if (!c.allowedScopes || c.allowedScopes.length === 0) {
      const scopes = c.type === 'SERVICE' ? [] : STANDARD_OIDC_SCOPES;
      await prisma.authClient.update({
        where: { id: c.id },
        data: { allowedScopes: scopes },
      });
      console.log(`Fixed allowedScopes for ${c.name} (${c.clientId}) → ${JSON.stringify(scopes)}`);
      fixedCount++;
    }
  }
  console.log(`\nFixed ${fixedCount} clients with empty allowedScopes.`);

  // ── 3. Verify ──
  const finalClients = await prisma.authClient.findMany({
    select: { name: true, clientId: true, type: true, status: true, allowedScopes: true, redirectUris: true, audience: true },
  });
  console.log('\n=== FINAL CLIENT REGISTRY ===');
  for (const c of finalClients) {
    console.log(`  ${c.clientId} (${c.type}) — ${c.status}`);
    console.log(`    scopes: ${JSON.stringify(c.allowedScopes)}`);
    console.log(`    redirectUris: ${JSON.stringify(c.redirectUris)}`);
    console.log(`    audience: ${c.audience ?? '(default)'}`);
  }

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error('Fix script failed:', err);
  process.exit(1);
});
