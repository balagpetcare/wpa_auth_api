import { Router } from 'express';
import authRoutes from '../modules/auth/auth.routes.js';
import usersRoutes from '../modules/users/users.routes.js';
import adminRoutes, { adminAuthRouter } from '../modules/admin/admin.routes.js';
import communicationRoutes from '../modules/communication/communication.routes.js';
import emailRoutes from '../modules/email/email.routes.js';
import oauthRoutes from '../modules/oauth/oauth.routes.js';
import { config } from '../config/index.js';
// NOTE (Phase 1 audit fix, see docs/wpa-central-auth-api-complete-audit.md):
// src/modules/clients/clients.routes.ts, src/modules/roles/roles.routes.ts, and
// src/modules/audit/audit.routes.ts are LEGACY/DUPLICATE modules. They were
// previously mounted at /clients, /roles, /audit with only `authGuard` (no
// requireAdmin/requirePermission), allowing ANY authenticated user to create
// OAuth clients, rotate client secrets, create roles, and read the full audit
// log. Fully admin-guarded equivalents already exist under /admin/clients,
// /admin/roles, and /admin/audit-logs (see modules/admin/admin.routes.ts).
// These legacy routers are intentionally left UNMOUNTED below. The files are
// kept (not deleted) in case they are needed for reference, but they must
// NOT be re-mounted without adding `authGuard, requireAdmin` (and ideally
// `requirePermission`) at the router level first.

const router = Router();

const externalCommunicationRoutes = (
  await import(process.env.NODE_ENV === 'production'
    ? '../modules/communication/events.routes.js'
    : '../modules/communication/events.routes.ts')
).default;

function buildOpenIdConfiguration(baseUrl: string) {
  return {
    issuer: config.OAUTH_ISSUER,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    jwks_uri: `${baseUrl}/oauth/jwks`,
    revocation_endpoint: `${baseUrl}/oauth/revoke`,
    introspection_endpoint: `${baseUrl}/oauth/introspect`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: config.JWT_RSA_PRIVATE_KEY ? ['RS256'] : ['HS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    code_challenge_methods_supported: ['S256'],
    claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email', 'email_verified', 'name', 'preferred_username', 'picture', 'roles'],
  };
}

router.get('/.well-known/openid-configuration', (_req, res) => {
  const baseUrl = config.API_PREFIX.replace(/\/$/, '');
  res.json(buildOpenIdConfiguration(baseUrl));
});

router.get('/health', (_req, res) => {
  res.json({ status: 'UP', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

router.use('/auth', authRoutes);
router.use('/users', usersRoutes);

// Admin auth login is public — mount before the guarded admin router
router.use('/admin/auth', adminAuthRouter);
router.use('/communication', externalCommunicationRoutes);
router.use('/admin/communication', communicationRoutes);
router.use('/admin', emailRoutes);
// All other /admin/* routes require authGuard + admin role (enforced inside adminRoutes)
router.use('/admin', adminRoutes);

router.use('/oauth', oauthRoutes);
// Legacy unprotected duplicates — DO NOT re-enable without admin guards. See note above.
// router.use('/clients', clientsRoutes);
// router.use('/roles', rolesRoutes);
// router.use('/audit', auditRoutes);

export default router;
