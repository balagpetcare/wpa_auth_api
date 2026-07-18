// Microsoft (Azure AD / Entra ID) login via id_token verification. Uses
// OIDC discovery (well-known configuration) for the tenant to resolve the
// JWKS URI, then verifies signature/iss/aud/exp/nonce exactly like the
// other OIDC adapters. Verified-email signal: Microsoft Entra ID does not
// reliably return an `email_verified` claim on the v2.0 id_token, so we
// only trust `email` as VERIFIED when `xms_edov` (Microsoft's "email
// domain owner verified" claim, present on work/school + some consumer
// tenants) is true; otherwise the email is treated as unverified — this is
// documented here rather than silently assuming Microsoft always verifies.
import { OAuthProvider } from '@prisma/client';
import { AppError, ErrorCodes } from '../../../lib/errors.js';
import { config } from '../../../config/index.js';
import { verifyIdToken } from './jwksVerifier.js';
import type { NormalizedIdentityProfile } from './types.js';

export function isMicrosoftLoginEnabled(): boolean {
  return Boolean(config.MICROSOFT_CLIENT_ID && config.MICROSOFT_CLIENT_ID.trim());
}

type DiscoveryDoc = { issuer: string; jwks_uri: string };
let discoveryCache: { tenant: string; doc: DiscoveryDoc; fetchedAt: number } | null = null;

async function getDiscoveryDoc(tenant: string): Promise<DiscoveryDoc> {
  if (discoveryCache && discoveryCache.tenant === tenant && Date.now() - discoveryCache.fetchedAt < 60 * 60 * 1000) {
    return discoveryCache.doc;
  }
  const url = `https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new AppError('Failed to load Microsoft OIDC discovery document.', ErrorCodes.INVALID_PROVIDER_TOKEN, 502);
  }
  const doc = (await res.json()) as DiscoveryDoc;
  discoveryCache = { tenant, doc, fetchedAt: Date.now() };
  return doc;
}

export async function verifyMicrosoftIdToken(idToken: string, opts?: { nonce?: string }): Promise<NormalizedIdentityProfile> {
  if (!isMicrosoftLoginEnabled()) {
    throw new AppError('Microsoft login is not enabled.', ErrorCodes.PROVIDER_DISABLED, 503);
  }
  const tenant = config.MICROSOFT_TENANT_ID || 'common';
  const discovery = await getDiscoveryDoc(tenant);
  // Multi-tenant "common"/"organizations"/"consumers" endpoints issue tokens
  // whose `iss` embeds the actual tenant GUID (not literally "common"), so
  // we cannot pin a single expected issuer string for those meta-tenants.
  // jose's issuer check is skipped in that case; iss format is still
  // validated to be a Microsoft STS issuer URL below to avoid accepting an
  // arbitrary issuer.
  const isMetaTenant = ['common', 'organizations', 'consumers'].includes(tenant);
  const payload = await verifyIdToken(idToken, {
    jwksUri: discovery.jwks_uri,
    ...(isMetaTenant ? {} : { issuer: discovery.issuer }),
    audience: config.MICROSOFT_CLIENT_ID!,
    nonce: opts?.nonce,
  });
  if (isMetaTenant) {
    const iss = typeof payload.iss === 'string' ? payload.iss : '';
    if (!/^https:\/\/login\.microsoftonline\.com\/[^/]+\/v2\.0$/.test(iss) && !/^https:\/\/sts\.windows\.net\//.test(iss)) {
      throw new AppError('Microsoft token issuer is not recognized.', ErrorCodes.INVALID_PROVIDER_TOKEN, 401);
    }
  }
  const sub = typeof payload.sub === 'string' ? payload.sub : '';
  if (!sub) throw new AppError('Microsoft token missing subject.', ErrorCodes.INVALID_PROVIDER_TOKEN, 401);
  return {
    provider: OAuthProvider.MICROSOFT,
    providerUserId: sub,
    email: typeof payload.email === 'string' ? payload.email : typeof payload.preferred_username === 'string' ? payload.preferred_username : undefined,
    emailVerified: payload.xms_edov === true,
    displayName: typeof payload.name === 'string' ? payload.name : undefined,
    rawClaims: payload as Record<string, unknown>,
  };
}
