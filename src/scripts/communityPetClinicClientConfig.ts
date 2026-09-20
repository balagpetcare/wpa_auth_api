export const COMMUNITY_PET_CLINIC_DEFAULTS = {
  name: 'Community Pet Clinic Web',
  slug: 'community-pet-clinic-web',
  clientId: 'community-pet-clinic-web',
  audience: 'community-pet-clinic',
  redirectUris: [
    'http://localhost:7701/auth/callback',
    'http://localhost:7702/auth/callback',
    'http://localhost:7703/auth/callback',
    'http://localhost:7704/auth/callback',
  ],
  postLogoutRedirectUris: [
    'http://localhost:7701/',
    'http://localhost:7702/',
    'http://localhost:7703/',
    'http://localhost:7704/',
  ],
  allowedOrigins: ['http://localhost:3002'],
  allowedScopes: ['openid', 'profile', 'email'],
} as const;

function csv(value: string | undefined, fallback: readonly string[]): string[] {
  if (!value?.trim()) return [...fallback];
  const values = value.split(',').map((item) => item.trim()).filter(Boolean);
  if (values.length === 0) throw new Error('Configured CSV value must not be empty.');
  return values;
}

export interface CommunityPetClinicClientConfig {
  readonly name: string;
  readonly slug: string;
  readonly clientId: string;
  readonly audience: string;
  readonly redirectUris: readonly string[];
  readonly postLogoutRedirectUris: readonly string[];
  readonly allowedOrigins: readonly string[];
  readonly allowedScopes: readonly string[];
  readonly clientSecret: string;
}

export function buildCommunityPetClinicClientConfig(
  env: Record<string, string | undefined>,
): CommunityPetClinicClientConfig {
  const clientSecret = env.CPC_CENTRAL_AUTH_CLIENT_SECRET?.trim();
  if (!clientSecret) throw new Error('Missing required environment variable: CPC_CENTRAL_AUTH_CLIENT_SECRET');
  return {
    ...COMMUNITY_PET_CLINIC_DEFAULTS,
    clientId: env.CPC_CENTRAL_AUTH_CLIENT_ID?.trim() || COMMUNITY_PET_CLINIC_DEFAULTS.clientId,
    audience: env.CPC_CENTRAL_AUTH_AUDIENCE?.trim() || COMMUNITY_PET_CLINIC_DEFAULTS.audience,
    redirectUris: csv(env.CPC_CENTRAL_AUTH_REDIRECT_URIS, COMMUNITY_PET_CLINIC_DEFAULTS.redirectUris),
    postLogoutRedirectUris: csv(
      env.CPC_CENTRAL_AUTH_POST_LOGOUT_REDIRECT_URIS,
      COMMUNITY_PET_CLINIC_DEFAULTS.postLogoutRedirectUris,
    ),
    allowedOrigins: csv(
      env.CPC_CENTRAL_AUTH_ALLOWED_ORIGINS,
      COMMUNITY_PET_CLINIC_DEFAULTS.allowedOrigins,
    ),
    clientSecret,
  };
}

export function publicBootstrapSummary(config: CommunityPetClinicClientConfig) {
  return {
    slug: config.slug,
    clientId: config.clientId,
    audience: config.audience,
    redirectCount: config.redirectUris.length,
    postLogoutRedirectCount: config.postLogoutRedirectUris.length,
    status: 'ACTIVE' as const,
  };
}
