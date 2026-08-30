import { prisma } from './db.js';
import { config } from '../config/index.js';
import { getCurrentSigningKeyMaterial } from './signingKeys.js';

export type IdTokenSigningAlg = 'HS256' | 'RS256';

function buildApiBaseUrl() {
  const issuer = config.OAUTH_ISSUER.replace(/\/$/, '');
  const prefix = config.API_PREFIX.startsWith('/') ? config.API_PREFIX.slice(1) : config.API_PREFIX;
  return new URL(`${prefix.replace(/\/$/, '')}/`, `${issuer}/`).toString().replace(/\/$/, '');
}

export async function getSupportedIdTokenSigningAlgs(): Promise<IdTokenSigningAlg[]> {
  const [clients, signingKey] = await Promise.all([
    prisma.authClient.findMany({
      where: { status: 'ACTIVE' },
      select: { oidcIdTokenSigningAlg: true },
    }),
    getCurrentSigningKeyMaterial(),
  ]);

  const supported = new Set<IdTokenSigningAlg>();
  const hasLegacyClients = clients.some((client) => !client.oidcIdTokenSigningAlg || client.oidcIdTokenSigningAlg === 'HS256');
  const hasRs256Clients = clients.some((client) => client.oidcIdTokenSigningAlg === 'RS256');

  if (hasLegacyClients) {
    supported.add('HS256');
  }

  if (hasRs256Clients && signingKey) {
    supported.add('RS256');
  }

  return Array.from(supported);
}

export async function buildOpenIdConfiguration() {
  const baseUrl = buildApiBaseUrl();
  const signingAlgs = await getSupportedIdTokenSigningAlgs();

  return {
    issuer: config.OAUTH_ISSUER.replace(/\/$/, ''),
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    jwks_uri: `${baseUrl}/oauth/jwks`,
    revocation_endpoint: `${baseUrl}/oauth/revoke`,
    introspection_endpoint: `${baseUrl}/oauth/introspect`,
    // RP-initiated logout (OpenID Connect Session Management / RP-Initiated
    // Logout 1.0). This IdP is API-first: the browser SSO session is the
    // token pair held by the hosted web app, so end-session validates the
    // client + post_logout_redirect_uri and the hosted /auth/logout page
    // performs the actual token revocation + local storage clear.
    end_session_endpoint: `${baseUrl}/oauth/end-session`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: signingAlgs.length > 0 ? signingAlgs : ['HS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email', 'email_verified', 'name', 'preferred_username', 'picture', 'roles'],
  };
}
