// Per-organization Enterprise identity provider login, config-driven via the
// EnterpriseIdentityProvider DB table (see prisma/schema.prisma) so an org
// can be onboarded without a code deploy.
//
// OIDC: fully implemented as an id_token verification path (the org's IdP
// hands the mobile/web client an id_token after its own auth-code+PKCE
// exchange, or a server-to-server auth-code exchange can be added later
// using the same clientId/clientSecretEncrypted/tokenUrl columns already on
// the model — that exchange endpoint itself is NOT implemented in this
// pass, only the config model + token-verification path). Verifies
// signature/iss/aud/exp/nonce against the org's own jwksUri, exactly like
// google/apple/microsoft.
//
// SAML: modeled in the schema (protocol=SAML, metadataUrl/entityId columns)
// but NOT implemented here. Calling verifyEnterpriseLogin against a
// SAML-protocol row throws PROVIDER_DISABLED with a NOT_IMPLEMENTED detail
// rather than faking a login — implementing SAML assertion validation
// properly (XML canonicalization, signature verification, replay
// protection) is a substantial separate effort out of scope for this pass;
// see the honesty note in the final report.
import { OAuthProvider } from '@prisma/client';
import { prisma } from '../../../lib/db.js';
import { AppError, ErrorCodes } from '../../../lib/errors.js';
import { verifyIdToken } from './jwksVerifier.js';
import type { NormalizedIdentityProfile } from './types.js';

export async function findEnterpriseProvider(orgSlug: string) {
  return prisma.enterpriseIdentityProvider.findUnique({ where: { orgSlug } });
}

export async function verifyEnterpriseOidcIdToken(
  orgSlug: string,
  idToken: string,
  opts?: { nonce?: string },
): Promise<NormalizedIdentityProfile> {
  const row = await findEnterpriseProvider(orgSlug);
  if (!row || !row.enabled) {
    throw new AppError('This organization is not configured for enterprise login.', ErrorCodes.PROVIDER_DISABLED, 503);
  }
  if (row.protocol !== 'OIDC') {
    throw new AppError(
      'SAML enterprise login is not implemented yet for this organization.',
      ErrorCodes.PROVIDER_DISABLED,
      501,
      { reason: 'NOT_IMPLEMENTED', protocol: row.protocol },
    );
  }
  if (!row.issuer || !row.jwksUri || !row.clientId) {
    throw new AppError('Enterprise OIDC provider is misconfigured.', 'PROVIDER_MISCONFIGURED', 400);
  }
  const payload = await verifyIdToken(idToken, {
    jwksUri: row.jwksUri,
    issuer: row.issuer,
    audience: row.clientId,
    nonce: opts?.nonce,
  });
  const sub = typeof payload.sub === 'string' ? payload.sub : '';
  if (!sub) throw new AppError('Enterprise token missing subject.', ErrorCodes.INVALID_PROVIDER_TOKEN, 401);
  return {
    provider: OAuthProvider.ENTERPRISE,
    // Namespaced so two different orgs' IdPs can never collide on the same
    // raw "sub" value and silently cross-link accounts between tenants.
    providerUserId: `${row.id}:${sub}`,
    email: typeof payload.email === 'string' ? payload.email : undefined,
    emailVerified: payload.email_verified === true,
    displayName: typeof payload.name === 'string' ? payload.name : undefined,
    rawClaims: payload as Record<string, unknown>,
  };
}
