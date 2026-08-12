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
  configurationReady: boolean;
  canTest: boolean;
  tested: boolean;
  readyForProduction: boolean;
  visibleOnLogin: boolean;
  canActivate: boolean;
  lifecycleStage: 'INACTIVE' | 'CONFIGURED' | 'ADMIN_TESTABLE' | 'TESTED' | 'PRODUCTION_READY' | 'ACTIVE';
  blockers: string[];
  testBlockers: string[];
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
    specificChecks: [],
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
    requiredScopes: ['instagram_business_basic'],
    requiresUserInfoUrl: true,
    publicLoginSupported: true,
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

function isNotRequired(value: unknown) {
  const normalized = normalizeString(value).toLowerCase();
  return ['not_required', 'not required', 'not-required', 'n/a', 'na', 'none', 'not applicable'].includes(normalized);
}

function isApprovedOrNotRequired(value: unknown) {
  return isApproved(value) || isNotRequired(value);
}

function isInstagramIntegrationTypeReady(value: unknown) {
  const normalized = normalizeString(value).toLowerCase().replace(/\s+/g, '_');
  return [
    'api_setup_with_instagram_login',
    'instagram_api_with_instagram_login',
    'instagram_business_login',
    'instagram_login',
  ].includes(normalized);
}

function pushCheck(checks: ProviderReadinessCheck[], warnings: string[], check: ProviderReadinessCheck) {
  checks.push(check);
  if (check.status === 'WARN') warnings.push(check.message);
}

function checkField(
  checks: ProviderReadinessCheck[],
  blockers: string[],
  testBlockers: string[],
  warnings: string[],
  key: string,
  label: string,
  ok: boolean,
  guidance: string,
  scope: 'both' | 'activation' | 'test' = 'both',
  warnOnly = false,
) {
  pushCheck(checks, warnings, {
    key,
    label,
    status: ok ? 'OK' : warnOnly ? 'WARN' : 'BLOCK',
    message: ok ? `${label} is configured.` : `${label} is not ready.`,
    guidance,
  });
  if (!ok && !warnOnly) {
    if (scope === 'both' || scope === 'activation') blockers.push(`${label} is not ready.`);
    if (scope === 'both' || scope === 'test') testBlockers.push(`${label} is not ready.`);
  }
}

export function computeProviderReadiness(row: SocialProviderWithExtras): ProviderReadiness {
  const spec = PROVIDER_SPECS[row.provider];
  const metadata = asRecord(row.providerMetadata ?? null);
  const checks: ProviderReadinessCheck[] = [];
  const blockers: string[] = [];
  const testBlockers: string[] = [];
  const warnings: string[] = [];
  const publicBase = config.PUBLIC_WEBSITE_ORIGIN.replace(/\/$/, '');
  const requiredRedirectUri = appCallbackUrl(row.provider);
  const hasAnyCoreConfig = Boolean(
    row.clientId?.trim()
      || row.clientSecretEncrypted?.trim()
      || row.authorizationUrl?.trim()
      || row.tokenUrl?.trim()
      || row.userInfoUrl?.trim()
      || (Array.isArray(row.scopes) && row.scopes.length > 0)
      || row.redirectUri?.trim(),
  );

  checkField(checks, blockers, testBlockers, warnings, 'clientId', 'Client ID configured', Boolean(row.clientId?.trim()), 'Enter the live client ID from the provider console.');
  checkField(checks, blockers, testBlockers, warnings, 'clientSecret', 'Client secret/private key configured', Boolean(row.clientSecretEncrypted?.trim()), 'Store the live client secret or private key encrypted in the provider record.');
  checkField(checks, blockers, testBlockers, warnings, 'authorizationUrl', 'Authorization URL', Boolean(row.authorizationUrl?.trim()), 'Enter the provider authorization endpoint exactly as published.');
  checkField(checks, blockers, testBlockers, warnings, 'tokenUrl', 'Token URL', Boolean(row.tokenUrl?.trim()), 'Enter the provider token endpoint exactly as published.');
  checkField(checks, blockers, testBlockers, warnings, 'userInfoUrl', 'User-info/OIDC configuration', !spec.requiresUserInfoUrl || Boolean(row.userInfoUrl?.trim()), 'Provide the OIDC/user-info endpoint required by this provider.');
  checkField(checks, blockers, testBlockers, warnings, 'scopes', 'Required scopes', spec.requiredScopes.every((scope) => row.scopes.includes(scope)), `Include the required scopes: ${spec.requiredScopes.join(', ')}.`);
  checkField(checks, blockers, testBlockers, warnings, 'redirectUri', 'Exact production redirect URI', row.redirectUri === requiredRedirectUri, `Register the exact callback URI: ${requiredRedirectUri}.`);
  if (row.provider === 'FACEBOOK') {
    checkField(checks, blockers, testBlockers, warnings, 'developerConsoleStatus', 'Developer-console setup status', isApprovedOrNotRequired(metadata.developerConsoleStatus), 'Complete the provider console configuration before production activation.', 'activation');
    checkField(checks, blockers, testBlockers, warnings, 'appMode', 'App mode', normalizeString(metadata.appMode).toLowerCase() === 'live', 'Switch the Meta app to Live before enabling production login.', 'activation');
    checkField(checks, blockers, testBlockers, warnings, 'appReviewStatus', 'App review status', isApprovedOrNotRequired(metadata.appReviewStatus ?? metadata.reviewStatus), 'Complete app review only when Meta requires it for the requested permissions.', 'activation');
    checkField(checks, blockers, testBlockers, warnings, 'businessVerificationStatus', 'Business verification status', isApprovedOrNotRequired(metadata.businessVerificationStatus ?? metadata.businessVerification ?? metadata.publisherVerificationStatus), 'Complete business or publisher verification only when Meta requires it for the requested permissions.', 'activation');
    checkField(checks, blockers, testBlockers, warnings, 'verifiedDomainStatus', 'Domain verification status', isApprovedOrNotRequired(metadata.verifiedDomainStatus), 'Verify the application domain in Meta if the deployment requires it.', 'activation');
    checkField(checks, blockers, testBlockers, warnings, 'dataDeletionCallbackStatus', 'Data-deletion callback/status URL', isApprovedOrNotRequired(metadata.dataDeletionCallbackStatus), 'Register the public deletion callback and status URL in the Meta app settings.', 'activation');
  } else {
    checkField(checks, blockers, testBlockers, warnings, 'homepageUrl', 'Homepage URL', Boolean(metadata.homepageUrl ?? publicBase), 'Register the production homepage URL in the provider console.');
    checkField(checks, blockers, testBlockers, warnings, 'privacyPolicyUrl', 'Privacy Policy URL', Boolean(metadata.privacyPolicyUrl ?? `${publicBase}/privacy-policy`), 'Register the public privacy policy URL in the provider console.');
    checkField(checks, blockers, testBlockers, warnings, 'termsUrl', 'Terms URL', Boolean(metadata.termsUrl ?? `${publicBase}/terms-of-service`), 'Register the public terms URL in the provider console.');
    checkField(checks, blockers, testBlockers, warnings, 'contactUrl', 'Contact/Support URL', Boolean(metadata.contactUrl ?? `${publicBase}/support`), 'Register a public support or contact URL in the provider console.');
    checkField(checks, blockers, testBlockers, warnings, 'dataDeletionUrl', 'Data Deletion URL', Boolean(metadata.dataDeletionUrl ?? `${publicBase}/data-deletion`), 'Register the public deletion instruction or callback URL.');
    checkField(checks, blockers, testBlockers, warnings, 'accountDeletionUrl', 'Account Deletion URL', Boolean(metadata.accountDeletionUrl ?? `${publicBase}/account-deletion`), 'Register the public account deletion URL.');
  }
  checkField(checks, blockers, testBlockers, warnings, 'testLoginStatus', 'Test-login status', Boolean(row.lastSuccessfulTestAt), 'Run a successful test login before enabling production traffic.', 'activation', true);
  if (!row.lastSuccessfulTestAt) {
    blockers.push('Test-login status is not ready.');
  }

  for (const specCheck of spec.specificChecks) {
    const value = metadata[specCheck.key];
    const ok = row.provider === 'INSTAGRAM' && specCheck.key === 'integrationType'
      ? isInstagramIntegrationTypeReady(value)
      : isApproved(value);
    const scope = row.provider === 'INSTAGRAM' && specCheck.key === 'integrationType' ? 'both' : 'activation';
    checkField(checks, blockers, testBlockers, warnings, specCheck.key, specCheck.label, ok, specCheck.guidance, scope);
  }

  for (const warningCheck of spec.warningChecks ?? []) {
    const value = metadata[warningCheck.key];
    checkField(checks, blockers, testBlockers, warnings, warningCheck.key, warningCheck.label, Boolean(value) && !['false', '0', 'no'].includes(normalizeString(value).toLowerCase()), warningCheck.guidance, 'activation', true);
  }

  const configurationReady = testBlockers.length === 0;
  const canTest = configurationReady;
  const tested = Boolean(row.lastSuccessfulTestAt);
  const readyForProduction = blockers.length === 0 && tested;
  const canActivate = readyForProduction && row.status !== 'ACTIVE';
  const visibleOnLogin = readyForProduction && row.status === 'ACTIVE' && row.showOnLogin && (row.provider !== 'INSTAGRAM' || spec.publicLoginSupported);
  const lifecycleStage: ProviderReadiness['lifecycleStage'] = row.status === 'ACTIVE' && readyForProduction
    ? 'ACTIVE'
    : readyForProduction
      ? 'PRODUCTION_READY'
      : tested
        ? 'TESTED'
        : configurationReady
          ? 'ADMIN_TESTABLE'
          : hasAnyCoreConfig
            ? 'CONFIGURED'
            : 'INACTIVE';

  return {
    configurationReady,
    canTest,
    tested,
    readyForProduction,
    visibleOnLogin,
    canActivate,
    lifecycleStage,
    blockers,
    testBlockers,
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
