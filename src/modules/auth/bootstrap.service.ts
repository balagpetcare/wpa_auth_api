// Public, unauthenticated bootstrap/config endpoint: everything a login
// screen needs to render itself (enabled methods/providers, whether
// email/phone is required, password policy, OTP cadence, branding) for a
// given AuthClient — resolved via the client's existing `clientId` public
// identifier (the SAME resolution auth.service.ts's resolveClient() already
// uses for login/register/refresh — no new client-identification
// mechanism). No secrets, no internal DB ids beyond what's already public
// (AuthClient.clientId, which BPA/Furtail already send on every request).
import { prisma } from '../../lib/db.js';
import { config } from '../../config/index.js';
import { isGoogleLoginEnabled } from './identity-providers/google.js';
import { isFacebookLoginEnabled } from './identity-providers/facebook.js';
import { isAppleLoginEnabled } from './identity-providers/apple.js';
import { isMicrosoftLoginEnabled } from './identity-providers/microsoft.js';

// The real, enforced password policy: registerSchema/changePasswordSchema in
// auth.routes.ts both use z.string().min(8) with no additional complexity
// rule today, so that is exactly what's surfaced here rather than a
// different, invented policy.
const PASSWORD_POLICY = {
  minLength: 8,
  requiresUppercase: false,
  requiresNumber: false,
  requiresSymbol: false,
};

export async function getBootstrapConfig(clientId?: string) {
  const client = clientId
    ? await prisma.authClient.findUnique({ where: { clientId }, include: { emailBranding: true } })
    : null;

  const allowedAuthMethods = client && client.allowedAuthMethods.length > 0 ? new Set(client.allowedAuthMethods) : null;
  const methodAllowed = (method: string) => !allowedAuthMethods || allowedAuthMethods.has(method);

  const providers: Array<{ id: string; displayName: string; enabled: boolean }> = [];
  if (methodAllowed('google')) providers.push({ id: 'google', displayName: 'Google', enabled: isGoogleLoginEnabled() });
  if (methodAllowed('facebook')) providers.push({ id: 'facebook', displayName: 'Facebook', enabled: isFacebookLoginEnabled() });
  if (methodAllowed('apple')) providers.push({ id: 'apple', displayName: 'Apple', enabled: isAppleLoginEnabled() });
  if (methodAllowed('microsoft')) providers.push({ id: 'microsoft', displayName: 'Microsoft', enabled: isMicrosoftLoginEnabled() });

  // Existing legacy social providers (github/instagram/linkedin/tiktok/x)
  // configured via SocialIdentityProviderConfig — surfaced the same way BPA
  // already consumes them (listPublicProviders in social.service.ts), just
  // folded into one bootstrap payload for a new client.
  const legacySocial = await prisma.socialIdentityProviderConfig.findMany({
    where: { status: 'ACTIVE', showOnLogin: true },
    orderBy: [{ placement: 'asc' }, { sortOrder: 'asc' }],
  });
  for (const row of legacySocial) {
    if (!methodAllowed(row.provider.toLowerCase())) continue;
    providers.push({ id: row.provider.toLowerCase(), displayName: row.displayName, enabled: true });
  }

  const enterpriseOrgs = await prisma.enterpriseIdentityProvider.findMany({
    where: { enabled: true },
    select: { orgSlug: true, displayName: true, protocol: true },
  });

  const loginMethods = {
    emailPassword: methodAllowed('email_password'),
    phonePassword: methodAllowed('phone_password'),
    emailOtp: methodAllowed('email_otp'),
    phoneOtp: methodAllowed('phone_otp'),
    whatsappOtp: methodAllowed('whatsapp_otp') && config.WHATSAPP_OTP_ENABLED,
    magicLink: false, // see docs — not implemented this pass, kept explicit/honest rather than omitted
  };

  const branding = client?.emailBranding
    ? {
        logoUrl: client.emailBranding.logoUrl,
        brandColor: client.emailBranding.brandColor,
        accentColor: client.emailBranding.accentColor,
        supportEmail: client.emailBranding.supportEmail,
        websiteUrl: client.emailBranding.websiteUrl,
        privacyUrl: client.emailBranding.privacyUrl,
        termsUrl: client.emailBranding.termsUrl,
      }
    : null;

  return {
    client: client ? { name: client.name, slug: client.slug } : null,
    registrationOpen: client ? client.registrationOpen : true,
    requiredProfileFields: client?.requiredProfileFields ?? [],
    loginMethods,
    providers,
    enterpriseOrganizations: enterpriseOrgs.map((o) => ({ orgSlug: o.orgSlug, displayName: o.displayName, protocol: o.protocol })),
    passwordPolicy: PASSWORD_POLICY,
    otp: {
      codeLength: config.OTP_LOGIN_CODE_LENGTH,
      expiryMinutes: config.OTP_LOGIN_EXPIRY_MINUTES,
      resendCooldownSeconds: config.OTP_LOGIN_RESEND_COOLDOWN_SECONDS,
    },
    branding,
  };
}
