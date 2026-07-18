// Normalized identity-provider interface for every OAuth/OIDC-style
// provider onboarded as part of the Furtail centralized-auth work (Google,
// Facebook, Apple, Microsoft, per-org Enterprise OIDC/SAML). Deliberately
// mirrors the existing `SocialProviderAdapter` shape in
// ../social-providers/base.ts (same NormalizedSocialProfile fields) so both
// families of adapters plug into the same account-linking logic
// (auth.identityLinking.service.ts) without a second normalization layer.
//
// Every adapter here verifies a provider-issued TOKEN (id_token or, for
// Facebook, an access token) SERVER-SIDE against the provider's official
// verification/JWKS endpoint. None of them ever trust an unverified decoded
// JWT payload — see jwksVerifier.ts.
import type { OAuthProvider } from '@prisma/client';

export type NormalizedIdentityProfile = {
  provider: OAuthProvider;
  providerUserId: string;
  email?: string;
  // true only when the PROVIDER's own token/response asserted the email is
  // verified (Google `email_verified`, Apple `email_verified`, Microsoft —
  // see microsoft.ts doc comment). Facebook does not assert email
  // verification at all, so Facebook profiles are always emailVerified:
  // false regardless of what Graph API returns for `email`.
  emailVerified: boolean;
  displayName?: string;
  avatarUrl?: string;
  rawClaims: Record<string, unknown>;
};

export type IdentityProviderAdapter = {
  provider: OAuthProvider;
  /** Whether this provider is usable given current config/DB state. */
  isEnabled(): Promise<boolean> | boolean;
};
