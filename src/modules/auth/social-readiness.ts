import type { OAuthProvider, Prisma, SocialIdentityProviderConfig } from '@prisma/client';
import { config } from '../../config/index.js';
import { appCallbackUrl } from './social-providers/base.js';

type ReadinessSeverity = 'BLOCK' | 'WARN' | 'OK';

export type ProviderReadinessCheck = {
  key: string;
  label: string;
  status: ReadinessSeverity;
  message: string;
  guidance?: string;
};

export type ProviderReadiness = {
  readyForProduction: boolean;
  visibleOnLogin: boolean;
  canActivate: boolean;
  blockers: string[];
  warnings: string[];
  checks: ProviderReadinessCheck[];
  publicUrls: {
    homepageUrl: string;
    privacyPolicyUrl: string;
    termsUrl: string;
    contactUrl: string;
    supportUrl: string;
    dataDeletionUrl: string;
    accountDeletionUrl: string;
  };
  providerSpecific: Record<string, unknown>;
  lastTestAt: Date | null;
  lastSuccessfulTestAt: Date | null;
  lastTestStatus: string | null;
  lastTestError: string | null;
};

type SocialProviderWithExtras = SocialIdentityProviderConfig & {
  providerMetadata?: Prisma.JsonValue | null;
  lastTestAt?: Date | null;
  lastSuccessfulTestAt?: Date | null;
  lastTestStatus?: string | null;
  lastTestError?: string | null;
};

type ProviderSpec = {
  requiredScopes: string[];
  requiresUserInfoUrl: boolean;
  publicLoginSupported: boolean;
  specificChecks: Array<{ key: string; label: string; guidance: string }>;
  warningChecks?: Array<{ key: string; label: string; guidance: string }>;
};

const PROVIDER_SPECS: Record<OAuthProvider, ProviderSpec> = {
  GOOGLE: {
    requiredScopes: ['openid', 'email', 'profile'],
    requiresUserInfoUrl: true,
    publicLoginSupported: true,
    specificChecks: [
      { key: 'oauthConsentScreenStatus', label: 'OAuth consent-screen status', guidance: 'Set the consent screen to production-ready and approved in Google Cloud Console.' },
      { key: 'authorizedDomainStatus', label: 'Authorized-domain status', guidance: 'Verify the app domain in Google Cloud and ensure the exact callback domain is authorized.' },
      { key: 'verificationStatus', label: 'Verification status', guidance: 'Complete Google verification before enabling production login if the scope set requires it.' },
    ],
  },
  FACEBOOK: {
    requiredScopes: ['email', 'public_profile'],
    requiresUserInfoUrl: true,
    publicLoginSupported: true,
    specificChecks: [
      { key: 'appMode', label: 'App mode', guidance: 'Switch the Meta app to Live before enabling production login.' },
      { key: 'appReview', label: 'App review', guidance: 'Ensure the login and data-access permissions have passed review.' },
      { key: 'businessVerification', label: 'Business verification', guidance: 'Complete Business Manager verification when required by the requested permissions.' },
      { key: 'dataDeletionCallbackStatus', label: 'Data-deletion callback/status URL', guidance: 'Register the public deletion callback and public status URL in the Meta app settings.' },
    ],
  },
  APPLE: {
    requiredScopes: ['name', 'email'],
    requiresUserInfoUrl: false,
    publicLoginSupported: true,
    specificChecks: [
      { key: 'teamId', label: 'Team ID', guidance: 'Provide the Apple Developer Team ID used to sign the app.' },
      { key: 'keyId', label: 'Key ID', guidance: 'Provide the Apple Sign In key identifier.' },
      { key: 'servicesId', label: 'Services ID', guidance: 'Use the exact Services ID registered for the app.' },
      { key: 'privateKeyConfigured', label: 'Private key configured', guidance: 'Store the Apple private key encrypted and verify it can be decrypted for token exchange.' },
      { key: 'domainAssociation', label: 'Domain association', guidance: 'Publish and verify the Apple domain association file for the production domain.' },
    ],
  },
  MICROSOFT: {
    requiredScopes: ['openid', 'email', 'profile'],
    requiresUserInfoUrl: true,
    publicLoginSupported: true,
    specificChecks: [
      { key: 'tenantMode', label: 'Tenant mode', guidance: 'Set the tenant to the intended production mode (single-tenant or multi-tenant).' },
      { key: 'publisherVerification', label: 'Publisher verification', guidance: 'Complete Microsoft publisher verification for production availability.' },
    ],
  },
  LINKEDIN: {
    requiredScopes: ['openid', 'profile', 'email'],
    requiresUserInfoUrl: true,
    publicLoginSupported: true,
    specificChecks: [
      { key: 'companyPageAssociation', label: 'Company Page association', guidance: 'Associate the LinkedIn app with the correct company page or organization.' },
      { key: 'openIdConnectProductApproval', label: 'OpenID Connect product approval', guidance: 'Ensure LinkedIn OpenID Connect access has been approved for production use.' },
    ],
  },
  TIKTOK: {
    requiredScopes: ['user.info.basic'],
    requiresUserInfoUrl: true,
    publicLoginSupported: true,
    specificChecks: [
      { key: 'loginKitApproval', label: 'Login Kit approval', guidance: 'Confirm TikTok Login Kit access has been approved for the production app.' },
      { key: 'appReviewStatus', label: 'App review status', guidance: 'Complete app review before enabling the provider in production.' },
    ],
  },
  X: {
    requiredScopes: ['tweet.read', 'users.read'],
    requiresUserInfoUrl: true,
    publicLoginSupported: true,
    specificChecks: [
      { key: 'oauthVersion', label: 'OAuth version', guidance: 'Use OAuth 2.0 with PKCE and the approved callback flow.' },
      { key: 'callbackUrlVerification', label: 'Callback URL verification', guidance: 'Verify the exact callback URL in the X developer console.' },
    ],
  },
  GITHUB: {
    requiredScopes: ['read:user', 'user:email'],
    requiresUserInfoUrl: true,
    publicLoginSupported: true,
    specificChecks: [
      { key: 'homepageStatus', label: 'OAuth App homepage status', guidance: 'Register the exact homepage URL in the GitHub OAuth App settings.' },
      { key: 'callbackStatus', label: 'OAuth callback status', guidance: 'Register the exact callback URL in the GitHub OAuth App settings.' },
    ],
  },
  INSTAGRAM: {
    requiredScopes: ['user_profile'],
    requiresUserInfoUrl: true,
    publicLoginSupported: false,
    specificChecks: [
      { key: 'integrationType', label: 'Integration type', guidance: 'Set the integration type to the exact supported Instagram flow used by the deployment.' },
    ],
    warningChecks: [
      { key: 'professionalAccountOnlyWarning', label: 'Professional-account-only warning', guidance: 'Do not advertise Instagram personal-account login unless this deployment explicitly supports it.' },
    ],
  },
  ENTERPRISE: {
    requiredScopes: [],
    requiresUserInfoUrl: false,
    publicLoginSupported: false,
    specificChecks: [
      { key: 'enterpriseSetup', label: 'Enterprise setup', guidance: 'Enterprise SSO readiness is managed separately from the public social-login provider list.' },
    ],
  },
};

function normalizeString(value: unknown) {
  return typeof value === 'string' ? value.trim() : '';
}

function asRecord(value: Prisma.JsonValue | null | undefined) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function isApproved(value: unknown) {
  const normalized = normalizeString(value).toLowerCase();
  return ['approved', 'verified', 'configured', 'live', 'enabled', 'active', 'complete', 'completed', 'passed', 'ok', 'success'].includes(normalized);
}

function pushCheck(checks: ProviderReadinessCheck[], blockers: string[], warnings: string[], check: ProviderReadinessCheck) {
  checks.push(check);
  if (check.status === 'BLOCK') blockers.push(check.message);
  if (check.status === 'WARN') warnings.push(check.message);
}

function checkField(
  checks: ProviderReadinessCheck[],
  blockers: string[],
  warnings: string[],
  key: string,
  label: string,
  ok: boolean,
  guidance: string,
  warnOnly = false,
) {
  pushCheck(checks, blockers, warnings, {
    key,
    label,
    status: ok ? 'OK' : warnOnly ? 'WARN' : 'BLOCK',
    message: ok ? `${label} is configured.` : `${label} is not ready.`,
    guidance,
  });
}

export function computeProviderReadiness(row: SocialProviderWithExtras): ProviderReadiness {
  const spec = PROVIDER_SPECS[row.provider];
  const metadata = asRecord(row.providerMetadata ?? null);
  const checks: ProviderReadinessCheck[] = [];
  const blockers: string[] = [];
  const warnings: string[] = [];
  const publicBase = config.PUBLIC_WEBSITE_ORIGIN.replace(/\/$/, '');
  const requiredRedirectUri = appCallbackUrl(row.provider);

  checkField(checks, blockers, warnings, 'status', 'Production environment status', row.environment === 'LIVE', 'Set the provider environment to LIVE before production activation.');
  checkField(checks, blockers, warnings, 'clientId', 'Client ID configured', Boolean(row.clientId?.trim()), 'Enter the live client ID from the provider console.');
  checkField(checks, blockers, warnings, 'clientSecret', 'Client secret/private key configured', Boolean(row.clientSecretEncrypted?.trim()), 'Store the live client secret or private key encrypted in the provider record.');
  checkField(checks, blockers, warnings, 'authorizationUrl', 'Authorization URL', Boolean(row.authorizationUrl?.trim()), 'Enter the provider authorization endpoint exactly as published.');
  checkField(checks, blockers, warnings, 'tokenUrl', 'Token URL', Boolean(row.tokenUrl?.trim()), 'Enter the provider token endpoint exactly as published.');
  checkField(checks, blockers, warnings, 'userInfoUrl', 'User-info/OIDC configuration', !spec.requiresUserInfoUrl || Boolean(row.userInfoUrl?.trim()), 'Provide the OIDC/user-info endpoint required by this provider.');
  checkField(checks, blockers, warnings, 'scopes', 'Required scopes', spec.requiredScopes.every((scope) => row.scopes.includes(scope)), `Include the required scopes: ${spec.requiredScopes.join(', ')}.`);
  checkField(checks, blockers, warnings, 'redirectUri', 'Exact production redirect URI', row.redirectUri === requiredRedirectUri, `Register the exact callback URI: ${requiredRedirectUri}.`);
  checkField(checks, blockers, warnings, 'homepageUrl', 'Homepage URL', Boolean(metadata.homepageUrl ?? publicBase), 'Register the production homepage URL in the provider console.');
  checkField(checks, blockers, warnings, 'privacyPolicyUrl', 'Privacy Policy URL', Boolean(metadata.privacyPolicyUrl ?? `${publicBase}/privacy-policy`), 'Register the public privacy policy URL in the provider console.');
  checkField(checks, blockers, warnings, 'termsUrl', 'Terms URL', Boolean(metadata.termsUrl ?? `${publicBase}/terms-of-service`), 'Register the public terms URL in the provider console.');
  checkField(checks, blockers, warnings, 'contactUrl', 'Contact/Support URL', Boolean(metadata.contactUrl ?? `${publicBase}/support`), 'Register a public support or contact URL in the provider console.');
  checkField(checks, blockers, warnings, 'dataDeletionUrl', 'Data Deletion URL', Boolean(metadata.dataDeletionUrl ?? `${publicBase}/data-deletion`), 'Register the public deletion instruction or callback URL.');
  checkField(checks, blockers, warnings, 'accountDeletionUrl', 'Account Deletion URL', Boolean(metadata.accountDeletionUrl ?? `${publicBase}/account-deletion`), 'Register the public account deletion URL.');
  checkField(checks, blockers, warnings, 'verifiedDomainStatus', 'Verified domain status', isApproved(metadata.verifiedDomainStatus), 'Verify the application domain in the provider console.', false);
  checkField(checks, blockers, warnings, 'developerConsoleStatus', 'Developer-console setup status', isApproved(metadata.developerConsoleStatus), 'Complete the provider console configuration before production activation.');
  checkField(checks, blockers, warnings, 'reviewStatus', 'Provider review status', isApproved(metadata.reviewStatus), 'Complete provider review and approval before production activation.');
  checkField(checks, blockers, warnings, 'businessVerificationStatus', 'Business/publisher verification status', isApproved(metadata.businessVerificationStatus) || isApproved(metadata.publisherVerificationStatus), 'Complete the required business or publisher verification.', false);
  checkField(checks, blockers, warnings, 'testLoginStatus', 'Test-login status', isApproved(metadata.testLoginStatus) || Boolean(row.lastSuccessfulTestAt), 'Run a successful test login before enabling production traffic.');

  for (const specCheck of spec.specificChecks) {
    const value = metadata[specCheck.key];
    checkField(checks, blockers, warnings, specCheck.key, specCheck.label, isApproved(value), specCheck.guidance);
  }

  for (const warningCheck of spec.warningChecks ?? []) {
    const value = metadata[warningCheck.key];
    checkField(checks, blockers, warnings, warningCheck.key, warningCheck.label, Boolean(value) && !['false', '0', 'no'].includes(normalizeString(value).toLowerCase()), warningCheck.guidance, true);
  }

  if (row.provider === 'INSTAGRAM' && !spec.publicLoginSupported) {
    pushCheck(checks, blockers, warnings, {
      key: 'instagramSupport',
      label: 'Instagram public-login support',
      status: 'WARN',
      message: 'Instagram personal-account login is not universally supported.',
      guidance: 'Keep Instagram hidden unless the deployment explicitly supports the configured flow.',
    });
  }

  const readyForProduction = blockers.length === 0 && Boolean(row.lastSuccessfulTestAt);
  const canActivate = readyForProduction && row.status === 'ACTIVE';
  const visibleOnLogin = readyForProduction && row.status === 'ACTIVE' && row.showOnLogin && (row.provider !== 'INSTAGRAM' || spec.publicLoginSupported);

  return {
    readyForProduction,
    visibleOnLogin,
    canActivate,
    blockers,
    warnings,
    checks,
    publicUrls: {
      homepageUrl: publicBase,
      privacyPolicyUrl: `${publicBase}/privacy-policy`,
      termsUrl: `${publicBase}/terms-of-service`,
      contactUrl: `${publicBase}/contact`,
      supportUrl: `${publicBase}/support`,
      dataDeletionUrl: `${publicBase}/data-deletion`,
      accountDeletionUrl: `${publicBase}/account-deletion`,
    },
    providerSpecific: metadata,
    lastTestAt: row.lastTestAt ?? null,
    lastSuccessfulTestAt: row.lastSuccessfulTestAt ?? null,
    lastTestStatus: row.lastTestStatus ?? null,
    lastTestError: row.lastTestError ?? null,
  };
}
