import { Router } from 'express';
import { z } from 'zod';
import { UserStatus, AuthClientStatus, AuthClientType, OAuthProvider, AdminNotificationCategory, AdminNotificationSeverity } from '@prisma/client';
import { DeletionRequestSource, DeletionRequestStatus, DeletionRequestType } from '@prisma/client';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import { requireAdmin } from '../../middleware/requireRole.js';
import { requirePermission } from '../../middleware/requirePermission.js';
import { validateBody } from '../../middleware/validate.js';
import { parsePagination, paginatedResponse } from '../../lib/pagination.js';
import * as adminService from './admin.service.js';
import * as authService from '../auth/auth.service.js';
import * as deletionService from '../deletion/deletion.service.js';
import * as socialService from '../auth/social.service.js';
import { avatarUpload } from '../../middleware/upload.js';
import { uploadAvatarBuffer } from '../../lib/avatarStorage.js';
import { AppError } from '../../lib/errors.js';
import { enterpriseRateLimit } from '../../lib/antiAbuse.js';
import { getOperationalSnapshot, renderPrometheusMetrics } from '../../lib/metrics.js';

const router = Router();


// All admin routes require a valid token + admin/super_admin role
router.use(authGuard, requireAdmin);

// â”€â”€â”€ Admin Auth â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// These are convenience wrappers over the shared auth service.
// Clients send clientId of the admin panel app.

const adminLoginSchema = z.object({
  emailOrUsername: z.string().min(1),
  password: z.string().min(1),
  clientId: z.string().optional(),
});

// POST /admin/auth/login  â€” public (no authGuard here, override router middleware)
const adminAuthRouter = Router();

adminAuthRouter.post('/login', enterpriseRateLimit({ route: 'admin-login', windowMs: 15 * 60 * 1000, max: 5, identifierFrom: (req) => `${req.body?.emailOrUsername ?? ''}:${req.ip ?? ''}`, threat: 'ADMIN_LOGIN_ABUSE', blockAfter: 8, blockTtlMs: 60 * 60 * 1000, blockScope: 'identifier' }), validateBody(adminLoginSchema), async (req, res, next) => {
  try {
    const result = await authService.loginUser(req.body, req);
    const isAdmin = result.user.roles.some((r) => ['admin', 'super_admin'].includes(r.toLowerCase()));
    if (!isAdmin) {
      res.status(403).json({ success: false, message: 'Access denied: admin role required.', code: 'FORBIDDEN' });
      return;
    }
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

adminAuthRouter.get('/me', authGuard, requireAdmin, async (req: AuthenticatedRequest, res, next) => {
  try {
    const user = await authService.getCurrentUser(req.user!.id);
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

const adminLogoutSchema = z.object({
  refreshToken: z.string().min(1).optional(),
});

adminAuthRouter.post('/logout', authGuard, requireAdmin, async (req: AuthenticatedRequest, res, next) => {
  try {
    const parsed = adminLogoutSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      res.status(400).json({
        success: false,
        message: 'Invalid logout request.',
        code: 'VALIDATION_ERROR',
        issues: parsed.error.flatten(),
      });
      return;
    }

    await authService.logoutUser(req.user!.id, parsed.data.refreshToken, req);
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    next(err);
  }
});

// Mount auth sub-router without the router-level authGuard (login must be public)
// We export adminAuthRouter separately and register it before the guarded routes.
export { adminAuthRouter };

// â”€â”€â”€ Users â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const usersQuerySchema = z.object({
  q: z.string().optional(),
  status: z.enum(['ACTIVE', 'SUSPENDED', 'DELETED', 'PENDING_VERIFICATION', 'ALL']).optional(),
  role: z.string().optional(),
  country: z.string().optional(),
  state: z.string().optional(),
  city: z.string().optional(),
  timezone: z.string().optional(),
  registrationSource: z.string().optional(),
  emailVerified: z.enum(['true', 'false', 'all']).optional(),
  phoneVerified: z.enum(['true', 'false', 'all']).optional(),
  hasEmail: z.enum(['true', 'false', 'all']).optional(),
  hasPhone: z.enum(['true', 'false', 'all']).optional(),
  loginActivity: z.enum(['never', 'today', '7d', '30d', '90d', '180d', 'all']).optional(),
  riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  hasOAuth: z.enum(['true', 'false', 'all']).optional(),
  provider: z.nativeEnum(OAuthProvider).optional(),
  createdFrom: z.string().datetime().optional(),
  createdTo: z.string().datetime().optional(),
  lastLoginFrom: z.string().datetime().optional(),
  lastLoginTo: z.string().datetime().optional(),
  lastPasswordChangedFrom: z.string().datetime().optional(),
  lastPasswordChangedTo: z.string().datetime().optional(),
  externalRefId: z.string().optional(),
  email: z.string().optional(),
  phone: z.string().optional(),
  username: z.string().optional(),
  userId: z.string().optional(),
  sortBy: z.enum(['createdAt', 'lastLoginAt', 'email', 'username', 'status']).optional(),
  sortOrder: z.enum(['asc', 'desc']).optional(),
  limit: z.coerce.number().min(1).max(100).optional().default(50),
  page: z.coerce.number().min(1).optional().default(1),
  includeCount: z.enum(['true', 'false']).optional()
});

// GET /admin/users/summary
router.get('/users/summary', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const summary = await adminService.getUsersSummary();
    res.json({ success: true, summary });
  } catch (err) {
    next(err);
  }
});

// Query schema for the admin-team ("Admin Users" panel) listing below. Kept
// next to usersQuerySchema for visibility even though it is also referenced
// by the invite/assign-existing section further down this file.
const adminUsersQuerySchema = z.object({
  q: z.string().optional(),
  role: z.string().optional(),
  status: z.string().optional(),
  limit: z.coerce.number().min(1).max(100).optional().default(20),
  cursor: z.string().optional(),
});

// GET /admin/users
// NOTE (Phase 1 audit fix, see docs/central-auth-api-admin-scalability-audit.md
// section E): this path used to be registered twice — once here backed by
// adminService.listUsers() (all users, rich filters), and again further down
// this file backed by adminService.listAdminUsers() (admin/super_admin
// operators only, with an `isLastSuperAdmin` flag). Express dispatches only
// the first-registered handler for a given method+path, so the second
// registration was completely unreachable dead code. The admin panel's
// admin-users feature (wpa_auth_admin/src/features/admin-users/api.ts) calls
// this exact path expecting the admin-team shape (and relies on
// `isLastSuperAdmin` to protect the last super admin), so that is the
// implementation kept live here. adminService.listUsers() (general
// all-users listing with rich filters) is left in admin.service.ts, unused,
// for the future dedicated end-user-management API called out as a missing
// module in the audit — it is intentionally not wired to a route yet.
router.get('/users', requirePermission('users:read', 'admin:read'), async (req: AuthenticatedRequest, res, next) => {
  try {
    const query = adminUsersQuerySchema.parse(req.query);
    const data = await adminService.listAdminUsers(query);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// GET /admin/users/:id
router.get('/users/:id', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const user = await adminService.getUserById((req.params.id as string));
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/users/:id/status
// NOTE (Phase 1 audit fix): this path used to be registered twice. The
// duplicate further down this file carried the self-suspend guard below, but
// Express dispatches only the first-registered handler for a given
// method+path, so that guard was dead code — an admin could suspend their
// own account. The guard now lives on this, the only registration of this
// route. Last-super-admin protection is enforced independently and
// authoritatively inside adminService.updateUserStatus() via
// guardLastSuperAdmin(), so it applies here regardless of which admin calls it.
router.patch('/users/:id/status', requirePermission('users:manage', 'admin:manage'), validateBody(z.object({ status: z.nativeEnum(UserStatus) })), async (req: AuthenticatedRequest, res, next) => {
  try {
    if (req.params.id === req.user!.id && req.body.status !== UserStatus.ACTIVE) {
      throw new AppError('You cannot change your own account status.', 'FORBIDDEN', 403);
    }
    const user = await adminService.updateUserStatus((req.params.id as string), req.body.status, req.user!.id, req);
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/users/:id
router.patch('/users/:id', requirePermission('users:manage', 'admin:manage'), validateBody(z.object({
  displayName: z.string().max(64).optional(),
  avatarUrl: z.string().url().optional(),
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/).optional(),
})), async (req: AuthenticatedRequest, res, next) => {
  try {
    const user = await adminService.updateUser((req.params.id as string), req.body, req.user!.id, req);
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

// DELETE /admin/users/:id
router.delete('/users/:id', requirePermission('users:manage', 'admin:manage'), async (req: AuthenticatedRequest, res, next) => {
  try {
    const user = await adminService.deleteUserAccount(req.params.id, req.user!.id, req);
    res.json({ success: true, message: 'User account deactivated safely.', user });
  } catch (err) {
    next(err);
  }
});

// POST /admin/users/:id/reset-password
router.post('/users/:id/reset-password', requirePermission('users:manage', 'admin:manage'), async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.resetUserPasswordAdmin(req.params.id, req.user!.id, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// POST /admin/users/:id/revoke-sessions
router.post('/users/:id/revoke-sessions', requirePermission('users:manage', 'admin:manage'), async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.revokeUserSessions(req.params.id, req.user!.id, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// GET /admin/users/:id/sessions
router.get('/users/:id/sessions', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const cursor = typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined;
    const limit = Number(req.query['limit'] ?? 50);
    const data = await adminService.getUserSessions((req.params.id as string), { cursor, limit });
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// GET /admin/users/:id/audit-logs
router.get('/users/:id/audit-logs', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const cursor = typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined;
    const limit = Number(req.query['limit'] ?? 50);
    const data = await adminService.getUserAuditLogs(req.params.id as string, { cursor, limit });
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// ─── End Users (Customer / Platform Accounts) ─────────────────────────────────
// Phase 2 module (docs/phase-2-core-identity-admin-modules.md). The admin
// panel previously only had a screen for internal admin operators (see the
// "─── Users ───" section above, backed by adminService.listAdminUsers()).
// adminService.listUsers() — a general, cursor-pagination-ready listing with
// rich filters (status/role/verification/OAuth/date-range) — already existed
// but was unused (it used to sit at the shadowed GET /users route fixed in
// Phase 1). It's reused here, unmodified, under its own dedicated path so it
// never collides with the admin-team routes again. getUserById/
// updateUserStatus/getUserSessions/getUserAuditLogs are likewise reused
// as-is — they already exclude password hashes and other sensitive fields
// via safeUserSelect, and updateUserStatus already runs guardLastSuperAdmin
// (a no-op for ordinary end users, but keeps the same safety net if a
// legacy record somehow holds an admin role).

// GET /admin/end-users
router.get('/end-users', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const query = usersQuerySchema.parse(req.query);

    const data = await adminService.listUsers({
      search: query.q,
      status: query.status as UserStatus | 'ALL',
      role: query.role,
      country: query.country,
      state: query.state,
      city: query.city,
      timezone: query.timezone,
      registrationSource: query.registrationSource,
      emailVerified: query.emailVerified,
      phoneVerified: query.phoneVerified,
      hasEmail: query.hasEmail,
      hasPhone: query.hasPhone,
      loginActivity: query.loginActivity,
      riskLevel: query.riskLevel,
      hasOAuth: query.hasOAuth,
      provider: query.provider,
      createdFrom: query.createdFrom ? new Date(query.createdFrom) : undefined,
      createdTo: query.createdTo ? new Date(query.createdTo) : undefined,
      lastLoginFrom: query.lastLoginFrom ? new Date(query.lastLoginFrom) : undefined,
      lastLoginTo: query.lastLoginTo ? new Date(query.lastLoginTo) : undefined,
      lastPasswordChangedFrom: query.lastPasswordChangedFrom ? new Date(query.lastPasswordChangedFrom) : undefined,
      lastPasswordChangedTo: query.lastPasswordChangedTo ? new Date(query.lastPasswordChangedTo) : undefined,
      externalRefId: query.externalRefId,
      email: query.email,
      phone: query.phone,
      username: query.username,
      userId: query.userId,
      sortBy: query.sortBy,
      sortOrder: query.sortOrder,
      limit: query.limit,
      page: query.page,
      includeCount: query.includeCount === 'true'
    });

    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// GET /admin/end-users/:id
router.get('/end-users/:id', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const user = await adminService.getUserById((req.params.id as string));
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

// GET /admin/end-users/:id/presence
router.get('/end-users/:id/presence', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const presence = await adminService.getUserPresence(req.params.id as string);
    res.json({ success: true, presence });
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/end-users/:id/status
router.patch('/end-users/:id/status', requirePermission('users:manage', 'admin:manage'), validateBody(z.object({ status: z.nativeEnum(UserStatus) })), async (req: AuthenticatedRequest, res, next) => {
  try {
    const user = await adminService.updateUserStatus((req.params.id as string), req.body.status, req.user!.id, req);
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

// GET /admin/end-users/:id/sessions
router.get('/end-users/:id/sessions', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const cursor = typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined;
    const limit = Number(req.query['limit'] ?? 50);
    const data = await adminService.getUserSessions((req.params.id as string), { cursor, limit });
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// GET /admin/end-users/:id/audit-logs
router.get('/end-users/:id/audit-logs', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const cursor = typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined;
    const limit = Number(req.query['limit'] ?? 50);
    const data = await adminService.getUserAuditLogs((req.params.id as string), { cursor, limit });
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// â”€â”€â”€ Roles & Permissions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Phase 2 role-permission management API (see
// docs/wpa-central-auth-api-complete-audit.md, "Phase 2 Role-Permission API Update").
//
// Permission keys: `roles:read` gates all GET routes below; `roles:manage` gates
// all mutating routes (create/update/delete role, and add/remove/replace
// permissions on a role). `roles:write`/`roles:delete` are also accepted where
// they existed previously, so any role that already had `roles:write` keeps
// working. `requirePermission()` still lets `super_admin` bypass all of these
// via its existing fast-path (see src/middleware/requirePermission.ts) — no
// change was needed there.
const permissionIdsOrKeysSchema = z.object({
  permissionIds: z.array(z.string().min(1)).optional(),
  permissionKeys: z.array(z.string().min(1)).optional(),
}).refine((d) => (d.permissionIds && d.permissionIds.length > 0) || (d.permissionKeys && d.permissionKeys.length > 0), {
  message: 'At least one of permissionIds or permissionKeys is required.',
});


// GET /admin/roles
router.get('/roles', requirePermission('roles:read'), async (_req, res, next) => {
  try {
    const roles = await adminService.listRoles();
    res.json({ success: true, roles });
  } catch (err) {
    next(err);
  }
});

// GET /admin/roles/:id
router.get('/roles/:id', requirePermission('roles:read'), async (req, res, next) => {
  try {
    const role = await adminService.getRoleById(req.params.id as string);
    res.json({ success: true, role });
  } catch (err) {
    next(err);
  }
});

// POST /admin/roles
router.post('/roles', requirePermission('roles:manage', 'roles:write'), validateBody(z.object({
  name: z.string().min(2),
  description: z.string().optional(),
  permissionIds: z.array(z.string().min(1)).optional(),
  permissionKeys: z.array(z.string().min(1)).optional(),
})), async (req: AuthenticatedRequest, res, next) => {
  try {
    const role = await adminService.createRoleAudited(req.body, req.user!.id, req);
    res.status(201).json({ success: true, role });
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/roles/:id
// NOTE: modifying the SUPER_ADMIN role's *permission assignments* (permissionIds/
// permissionKeys) is blocked unless the actor themself holds the super_admin
// role — see adminService.assertCanModifySuperAdminPermissions(). Renaming/
// re-describing the SUPER_ADMIN role (name/description only, no permission
// change) is still allowed for any admin with roles:manage.
router.patch('/roles/:id', requirePermission('roles:manage', 'roles:write'), validateBody(z.object({
  name: z.string().min(2).optional(),
  description: z.string().optional(),
  permissionIds: z.array(z.string().min(1)).optional(),
  permissionKeys: z.array(z.string().min(1)).optional(),
})), async (req: AuthenticatedRequest, res, next) => {
  try {
    const role = await adminService.updateRole(
      req.params.id as string,
      req.body,
      req.user!.id,
      req.user!.roles ?? [],
      req,
    );
    res.json({ success: true, role });
  } catch (err) {
    next(err);
  }
});

// DELETE /admin/roles/:id
// Blocked if the role is SUPER_ADMIN, or if any user is still assigned to it.
router.delete('/roles/:id', requirePermission('roles:manage', 'roles:delete'), async (req: AuthenticatedRequest, res, next) => {
  try {
    await adminService.deleteRole(req.params.id as string, req.user!.id, req);
    res.json({ success: true, message: 'Role deleted.' });
  } catch (err) {
    next(err);
  }
});

// POST /admin/roles/:id/permissions — add one or more permissions to a role.
router.post('/roles/:id/permissions', requirePermission('roles:manage'), validateBody(permissionIdsOrKeysSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    const role = await adminService.addPermissionsToRole(
      req.params.id as string,
      req.body,
      req.user!.id,
      req.user!.roles ?? [],
      req,
    );
    res.json({ success: true, role, message: 'Permissions added to role.' });
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/roles/:id/permissions — replace the full permission set for a role.
router.patch('/roles/:id/permissions', requirePermission('roles:manage'), validateBody(z.object({
  permissionIds: z.array(z.string().min(1)).optional(),
  permissionKeys: z.array(z.string().min(1)).optional(),
})), async (req: AuthenticatedRequest, res, next) => {
  try {
    const role = await adminService.replaceRolePermissions(
      req.params.id as string,
      req.body,
      req.user!.id,
      req.user!.roles ?? [],
      req,
    );
    res.json({ success: true, role, message: 'Role permissions replaced.' });
  } catch (err) {
    next(err);
  }
});

// DELETE /admin/roles/:id/permissions/:permissionId
router.delete('/roles/:id/permissions/:permissionId', requirePermission('roles:manage'), async (req: AuthenticatedRequest, res, next) => {
  try {
    const role = await adminService.removePermissionFromRole(
      req.params.id as string,
      req.params.permissionId as string,
      req.user!.id,
      req.user!.roles ?? [],
      req,
    );
    res.json({ success: true, role, message: 'Permission removed from role.' });
  } catch (err) {
    next(err);
  }
});

// GET /admin/permissions
router.get('/permissions', requirePermission('roles:read', 'permissions:read'), async (_req, res, next) => {
  try {
    const permissions = await adminService.listPermissions();
    res.json({ success: true, permissions });
  } catch (err) {
    next(err);
  }
});

// POST /admin/users/:id/roles
// NOTE (Phase 1 audit fix — privilege escalation): this route previously had
// no permission check at all beyond the router-level requireAdmin, so any
// admin-level account (not just super_admin) could grant any role, including
// SUPER_ADMIN, to any user. Gated the same way as the sibling
// PATCH /users/:id/roles route below.
router.post('/users/:id/roles', requirePermission('roles:manage', 'users:manage'), validateBody(z.object({ roleId: z.string().min(1) })), async (req: AuthenticatedRequest, res, next) => {
  try {
    await adminService.assignRoleToUser((req.params.id as string), req.body.roleId, req.user!.id, req);
    res.json({ success: true, message: 'Role assigned.' });
  } catch (err) {
    next(err);
  }
});

// DELETE /admin/users/:id/roles/:roleId
// NOTE (Phase 1 audit fix — privilege escalation): same gap as above, applied
// to role removal.
router.delete('/users/:id/roles/:roleId', requirePermission('roles:manage', 'users:manage'), async (req: AuthenticatedRequest, res, next) => {
  try {
    await adminService.removeRoleFromUser((req.params.id as string), (req.params.roleId as string), req.user!.id, req);
    res.json({ success: true, message: 'Role removed.' });
  } catch (err) {
    next(err);
  }
});

// â”€â”€â”€ Clients â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// GET /admin/clients
router.get('/clients', async (req, res, next) => {
  try {
    const pagination = parsePagination(req);
    const search = req.query['search'] as string | undefined;
    const status = req.query['status'] as AuthClientStatus | undefined;
    const { clients, total } = await adminService.listClients({ search, status, pagination });
    res.json({ success: true, ...paginatedResponse(clients, total, pagination) });
  } catch (err) {
    next(err);
  }
});

// POST /admin/clients
router.post('/clients', validateBody(z.object({
  name: z.string().min(2),
  slug: z.string().min(2).regex(/^[a-z0-9-]+$/),
  type: z.nativeEnum(AuthClientType),
  allowedOrigins: z.array(z.string()).optional(),
  redirectUris: z.array(z.string()).optional(),
  allowedScopes: z.array(z.string()).optional(),
})), async (_req, res, next) => {
  try {
    const { client, clientSecret } = await adminService.createClient(_req.body);
    res.status(201).json({ success: true, client, clientSecret });
  } catch (err) {
    next(err);
  }
});

// GET /admin/clients/:id
router.get('/clients/:id', async (req, res, next) => {
  try {
    const client = await adminService.getClientById((req.params.id as string));
    res.json({ success: true, client });
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/clients/:id
router.patch('/clients/:id', validateBody(z.object({
  name: z.string().min(2).optional(),
  allowedOrigins: z.array(z.string()).optional(),
  redirectUris: z.array(z.string()).optional(),
  allowedScopes: z.array(z.string()).optional(),
})), async (req, res, next) => {
  try {
    const client = await adminService.updateClient((req.params.id as string), req.body);
    res.json({ success: true, client });
  } catch (err) {
    next(err);
  }
});

// POST /admin/clients/:id/rotate-secret
router.post('/clients/:id/rotate-secret', async (req: AuthenticatedRequest, res, next) => {
  try {
    const clientSecret = await adminService.rotateClientSecret((req.params.id as string), req.user!.id, req);
    res.json({ success: true, clientSecret, message: 'Store this secret now â€” it will not be shown again.' });
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/clients/:id/status
router.patch('/clients/:id/status', validateBody(z.object({ status: z.nativeEnum(AuthClientStatus) })), async (req: AuthenticatedRequest, res, next) => {
  try {
    await adminService.updateClientStatus((req.params.id as string), req.body.status, req.user!.id, req);
    res.json({ success: true, message: 'Client status updated.' });
  } catch (err) {
    next(err);
  }
});

// â”€â”€â”€ Audit & Stats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// GET /admin/audit-logs
router.get('/audit-logs', async (req, res, next) => {
  try {
    const userId = req.query['userId'] as string | undefined;
    const action = req.query['action'] as string | undefined;
    const cursor = req.query['cursor'] as string | undefined;
    const limit = Number(req.query['limit'] ?? 50);
    const data = await adminService.listAuditLogs({ userId, action, cursor, limit });
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// GET /admin/security-events
router.get('/security-events', async (req, res, next) => {
  try {
    const userId = req.query['userId'] as string | undefined;
    const type = req.query['type'] as string | undefined;
    const severity = req.query['severity'] as string | undefined;
    const resolvedParam = req.query['resolved'] as string | undefined;
    const resolved = resolvedParam === 'true' ? true : resolvedParam === 'false' ? false : undefined;
    const createdFrom = req.query['createdFrom'] as string | undefined;
    const createdTo = req.query['createdTo'] as string | undefined;
    const cursor = req.query['cursor'] as string | undefined;
    const limit = Number(req.query['limit'] ?? 50);
    const createdFromDate = createdFrom ? new Date(createdFrom) : undefined;
    const createdToDate = createdTo ? new Date(createdTo) : undefined;
    if ((createdFromDate && Number.isNaN(createdFromDate.getTime())) || (createdToDate && Number.isNaN(createdToDate.getTime()))) {
      throw new AppError('Invalid date filter provided.', 'VALIDATION_ERROR', 400);
    }
    const data = await adminService.listSecurityEvents({
      userId,
      type,
      severity,
      resolved,
      createdFrom: createdFromDate,
      createdTo: createdToDate,
      cursor,
      limit,
    });
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// â”€â”€â”€ Deletion Requests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

router.get('/deletion-requests', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const query = deletionRequestsQuerySchema.parse(req.query);
    const data = await deletionService.listDeletionRequests({
      status: query.status,
      requestType: query.requestType,
      provider: query.provider,
      requestSource: query.requestSource,
      search: query.search,
      page: query.page,
      limit: query.limit,
    });
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

router.get('/deletion-requests/:id', requirePermission('users:read', 'admin:read'), async (req, res, next) => {
  try {
    const data = await deletionService.getDeletionRequestDetail(req.params.id);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

router.patch('/deletion-requests/:id', requirePermission('users:manage', 'admin:manage'), validateBody(z.object({
  action: z.enum(['approve', 'reject', 'retry', 'cancel']),
  reason: z.string().max(300).optional(),
})), async (req: AuthenticatedRequest, res, next) => {
  try {
    const { action, reason } = req.body;
    let data;
    switch (action) {
      case 'approve':
        data = await deletionService.approveDeletionRequest(req.params.id, req.user!.id, req);
        break;
      case 'reject':
        data = await deletionService.rejectDeletionRequest(req.params.id, req.user!.id, reason ?? null, req);
        break;
      case 'retry':
        data = await deletionService.retryDeletionRequest(req.params.id, req.user!.id, req);
        break;
      case 'cancel':
        data = await deletionService.cancelDeletionRequestById(req.params.id, req);
        break;
      default:
        throw new AppError('Unsupported deletion action.', 'VALIDATION_ERROR', 400);
    }
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// GET /admin/dashboard/stats
router.get('/dashboard/stats', async (_req, res, next) => {
  try {
    const stats = await adminService.getDashboardStats();
    res.json({ success: true, stats });
  } catch (err) {
    next(err);
  }
});

// GET /admin/metrics
router.get('/metrics', requirePermission('admin:read'), async (_req, res) => {
  res.type('text/plain').send(renderPrometheusMetrics());
});

// GET /admin/metrics/summary
router.get('/metrics/summary', requirePermission('admin:read'), async (_req, res, next) => {
  try {
    const data = await getOperationalSnapshot();
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// ─── Social Providers ────────────────────────────────────────────────────────

// GET /admin/social-providers
router.get('/social-providers', async (_req, res, next) => {
  try {
    const providers = await adminService.listSocialProviders();
    res.json({ success: true, providers });
  } catch (err) {
    next(err);
  }
});

router.get('/social-providers/:id', async (req, res, next) => {
  try {
    const provider = await adminService.getSocialProviderById(req.params.id);
    res.json({ success: true, provider });
  } catch (err) {
    next(err);
  }
});

const socialProviderSchema = z.object({
  provider: z.nativeEnum(OAuthProvider),
  displayName: z.string().min(1),
  clientId: z.string().nullable().optional(),
  clientSecret: z.string().nullable().optional(),
  authorizationUrl: z.string().url(),
  tokenUrl: z.string().url(),
  userInfoUrl: z.string().url().nullable().optional(),
  scopes: z.array(z.string()).default([]),
  redirectUri: z.string().url(),
  providerMetadata: z.record(z.string(), z.unknown()).optional(),
  status: z.enum(['ACTIVE', 'INACTIVE']),
  environment: z.enum(['SANDBOX', 'LIVE']),
  placement: z.enum(['MAIN', 'MORE', 'HIDDEN']),
  sortOrder: z.coerce.number().int().default(0),
  showOnLogin: z.boolean().default(true),
});

router.post('/social-providers', validateBody(socialProviderSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    const provider = await adminService.createSocialProvider(req.body, req.user!.id, req);
    res.status(201).json({ success: true, provider });
  } catch (err) {
    next(err);
  }
});

router.patch('/social-providers/:id', validateBody(socialProviderSchema.partial()), async (req: AuthenticatedRequest, res, next) => {
  try {
    const provider = await adminService.updateSocialProvider(req.params.id, req.body, req.user!.id, req);
    res.json({ success: true, provider });
  } catch (err) {
    next(err);
  }
});

router.patch('/social-providers/:id/status', validateBody(z.object({ status: z.enum(['ACTIVE', 'INACTIVE']) })), async (req: AuthenticatedRequest, res, next) => {
  try {
    const provider = await adminService.updateSocialProviderStatus(req.params.id, req.body.status, req.user!.id, req);
    res.json({ success: true, provider });
  } catch (err) {
    next(err);
  }
});

router.post('/social-providers/:id/test', async (req: AuthenticatedRequest, res, next) => {
  try {
    const data = await socialService.testProvider(req.params.id, req.user!.id, req);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

router.delete('/social-providers/:id', async (req: AuthenticatedRequest, res, next) => {
  try {
    const provider = await adminService.deleteSocialProvider(req.params.id, req.user!.id, req);
    res.json({ success: true, provider });
  } catch (err) {
    next(err);
  }
});

// ─── Global Sessions ────────────────────────────────────────────────────────
router.get('/sessions', async (req, res, next) => {
  try {
    const search = req.query['search'] as string | undefined;
    const status = req.query['status'] as string | undefined;
    const userId = req.query['userId'] as string | undefined;
    const cursor = req.query['cursor'] as string | undefined;
    const limit = Number(req.query['limit'] ?? 50);
    const data = await adminService.listGlobalSessions({ search, status, userId, cursor, limit });
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

router.delete('/sessions/:id', async (req: AuthenticatedRequest, res, next) => {
  try {
    const session = await adminService.revokeSession(req.params.id, req.user!.id, req);
    res.json({ success: true, session });
  } catch (err) {
    next(err);
  }
});

// ─── OAuth Accounts ─────────────────────────────────────────────────────────
router.get('/oauth-accounts', async (req, res, next) => {
  try {
    const pagination = parsePagination(req);
    const search = req.query['search'] as string | undefined;
    const provider = req.query['provider'] as string | undefined;
    const userId = req.query['userId'] as string | undefined;
    const { accounts, total } = await adminService.listOAuthAccounts({ search, provider, userId, pagination });
    res.json({ success: true, ...paginatedResponse(accounts, total, pagination) });
  } catch (err) {
    next(err);
  }
});

router.delete('/oauth-accounts/:id', async (req: AuthenticatedRequest, res, next) => {
  try {
    await adminService.unlinkOAuthAccount(req.params.id, req.user!.id, req);
    res.json({ success: true, message: 'OAuth account unlinked' });
  } catch (err) {
    next(err);
  }
});

// ─── Settings ───────────────────────────────────────────────────────────────
router.get('/settings', async (_req, res, next) => {
  try {
    const settings = adminService.getSettings();
    res.json({ success: true, settings });
  } catch (err) {
    next(err);
  }
});

// ─── My Account ───────────────────────────────────────────────────────────────
// NOTE (Phase 1 audit fix): POST /users/:id/reset-password was previously defined
// twice in this file. The duplicate (which called adminService.triggerPasswordReset)
// has been removed here — the earlier definition above (using
// adminService.resetUserPasswordAdmin) is the intended implementation: it writes
// an audit log AND creates an admin notification for the affected user, whereas
// triggerPasswordReset only wrote an audit log. adminService.triggerPasswordReset
// is now unused; left in admin.service.ts in case a future email-based reset flow
// needs it, but it is not wired to any route.
router.get('/account/me', async (req: AuthenticatedRequest, res, next) => {
  try {
    const account = await adminService.getMyAccount(req.user!.id);
    res.json({ success: true, account });
  } catch (err) {
    next(err);
  }
});

router.patch('/account/me', async (req: AuthenticatedRequest, res, next) => {
  try {
    const account = await adminService.updateMyAccount(req.user!.id, req.body, req);
    res.json({ success: true, account });
  } catch (err) {
    next(err);
  }
});

router.post('/account/avatar', (req, res, next) => {
  avatarUpload.single('avatar')(req, res, async (error) => {
    if (error) {
      next(error);
      return;
    }
    try {
      const file = (req as AuthenticatedRequest & { file?: Express.Multer.File }).file;
      if (!file) throw new AppError('Avatar file is required.', 'VALIDATION_ERROR', 400);
      const key = await uploadAvatarBuffer(file.buffer, file.mimetype);
      const avatarUrl = adminService.buildAvatarPublicUrl(key);
      const data = await adminService.updateMyAvatar((req as AuthenticatedRequest).user!.id, avatarUrl, req);
      res.json({ success: true, data, message: 'Profile picture updated successfully.' });
    } catch (err) {
      next(err);
    }
  });
});

router.delete('/account/avatar', async (req: AuthenticatedRequest, res, next) => {
  try {
    const data = await adminService.removeMyAvatar(req.user!.id, req);
    res.json({ success: true, data, message: 'Profile picture removed successfully.' });
  } catch (err) {
    next(err);
  }
});

const changeMyPasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8),
  confirmPassword: z.string().min(8),
});

router.post(
  '/account/change-password',
  enterpriseRateLimit({
    route: 'admin-change-password',
    windowMs: 15 * 60 * 1000,
    max: 5,
    identifierFrom: (req) => (req as AuthenticatedRequest).user!.id,
    threat: 'SUSPICIOUS_ACTIVITY_BLOCKED',
    blockAfter: 8,
    blockTtlMs: 60 * 60 * 1000,
    blockScope: 'identifier',
  }),
  validateBody(changeMyPasswordSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const result = await adminService.changeMyPassword(req.user!.id, req.body, req);
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

const notificationsQuerySchema = z.object({
  status: z.enum(['unread', 'read', 'archived', 'all']).optional().default('all'),
  category: z.nativeEnum(AdminNotificationCategory).optional(),
  severity: z.nativeEnum(AdminNotificationSeverity).optional(),
  search: z.string().optional(),
  createdFrom: z.string().datetime().optional(),
  createdTo: z.string().datetime().optional(),
  limit: z.coerce.number().min(1).max(50).optional().default(20),
  cursor: z.string().optional(),
});

const deletionRequestsQuerySchema = z.object({
  status: z.union([z.nativeEnum(DeletionRequestStatus), z.literal('ALL')]).optional().default('ALL'),
  requestType: z.union([z.nativeEnum(DeletionRequestType), z.literal('ALL')]).optional().default('ALL'),
  provider: z.union([z.nativeEnum(OAuthProvider), z.literal('ALL')]).optional().default('ALL'),
  requestSource: z.union([z.nativeEnum(DeletionRequestSource), z.literal('ALL')]).optional().default('ALL'),
  search: z.string().optional(),
  page: z.coerce.number().min(1).optional().default(1),
  limit: z.coerce.number().min(1).max(100).optional().default(20),
});

const deletionRequestActionSchema = z.object({
  action: z.enum(['approve', 'reject', 'retry', 'cancel']),
  reason: z.string().max(300).optional(),
});

router.get('/notifications', async (req: AuthenticatedRequest, res, next) => {
  try {
    const query = notificationsQuerySchema.parse(req.query);
    const data = await adminService.listMyNotifications({
      userId: req.user!.id,
      status: query.status,
      category: query.category,
      severity: query.severity,
      search: query.search,
      createdFrom: query.createdFrom ? new Date(query.createdFrom) : undefined,
      createdTo: query.createdTo ? new Date(query.createdTo) : undefined,
      limit: query.limit,
      cursor: query.cursor,
    });
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

router.get('/notifications/unread-count', async (req: AuthenticatedRequest, res, next) => {
  try {
    const data = await adminService.getMyUnreadNotificationCount(req.user!.id);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

router.patch('/notifications/read-all', async (req: AuthenticatedRequest, res, next) => {
  try {
    const data = await adminService.markAllNotificationsRead(req.user!.id);
    res.json({ success: true, data, message: 'Notifications marked as read.' });
  } catch (err) {
    next(err);
  }
});

router.delete('/notifications/archived', async (req: AuthenticatedRequest, res, next) => {
  try {
    const data = await adminService.clearArchivedNotifications(req.user!.id);
    res.json({ success: true, data, message: 'Archived notifications cleared.' });
  } catch (err) {
    next(err);
  }
});

router.patch('/notifications/:notificationId/read', async (req: AuthenticatedRequest, res, next) => {
  try {
    const notification = await adminService.markNotificationRead(req.user!.id, req.params.notificationId);
    res.json({ success: true, data: notification });
  } catch (err) {
    next(err);
  }
});

router.patch('/notifications/:notificationId/unread', async (req: AuthenticatedRequest, res, next) => {
  try {
    const notification = await adminService.markNotificationUnread(req.user!.id, req.params.notificationId);
    res.json({ success: true, data: notification });
  } catch (err) {
    next(err);
  }
});

router.delete('/notifications/:notificationId', async (req: AuthenticatedRequest, res, next) => {
  try {
    const notification = await adminService.dismissNotification(req.user!.id, req.params.notificationId);
    res.json({ success: true, data: notification, message: 'Notification dismissed.' });
  } catch (err) {
    next(err);
  }
});

// ─── Admin Team / Invitation System ──────────────────────────────────────────
// NOTE (Phase 1 audit fix): GET /users, GET /users/:id, PATCH /users/:id, and
// PATCH /users/:id/status used to be re-registered in this section, duplicating
// the routes already defined above under "─── Users ───". Express only ever
// dispatched the first-registered handler for each of those paths, so these
// copies were unreachable dead code (and in the case of PATCH /users/:id/status,
// the copy that carried the self-suspend guard was the dead one — see the fix
// above). They have been removed; adminInviteSchema and adminUserRolesUpdateSchema
// remain in use by POST /users/invite and PATCH /users/:id/roles below.

const adminInviteSchema = z.object({
  email: z.string().email(),
  roleIds: z.array(z.string().min(1)).min(1),
  message: z.string().optional(),
});

const adminUserRolesUpdateSchema = z.object({
  roleIds: z.array(z.string().min(1)).min(1).optional(),
  roleId: z.string().min(1).optional(),
});

// POST /admin/users/invite
router.post('/users/invite', requirePermission('users:manage', 'admin:manage'), validateBody(adminInviteSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.createAdminInvitation({
      email: req.body.email,
      roleIds: req.body.roleIds,
      message: req.body.message,
      actorId: req.user!.id,
      req,
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/users/:id/roles
router.patch('/users/:id/roles', requirePermission('roles:manage', 'users:manage'), validateBody(adminUserRolesUpdateSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    const requestedRoleIds: string[] = req.body.roleIds ?? (req.body.roleId ? [req.body.roleId] : []);
    if (requestedRoleIds.length === 0) {
      throw new AppError('At least one roleId is required.', 'VALIDATION_ERROR', 400);
    }

    const currentUser = await adminService.getUserById(req.params.id as string);
    const currentRoleIds = (currentUser.roles || []).map((r: any) => r.id);

    const toAdd = requestedRoleIds.filter((id) => !currentRoleIds.includes(id));
    const toRemove = currentRoleIds.filter((id) => !requestedRoleIds.includes(id));

    for (const roleId of toAdd) {
      await adminService.assignRoleToUser(req.params.id as string, roleId, req.user!.id, req);
    }
    for (const roleId of toRemove) {
      await adminService.removeRoleFromUser(req.params.id as string, roleId, req.user!.id, req);
    }

    const user = await adminService.getUserById(req.params.id as string);
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

const assignExistingSchema = z.object({
  userId: z.string().min(1),
  roleIds: z.array(z.string()),
});

// NOTE (Phase 1 audit fix — privilege escalation): user-to-admin promotion
// previously had no permission check beyond the router-level requireAdmin,
// letting any admin-level account grant itself or others admin roles.
router.post('/admin-users/assign-existing', requirePermission('users:manage', 'admin:manage'), validateBody(assignExistingSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.assignExistingUserAdmin({
      userId: req.body.userId,
      roleIds: req.body.roleIds,
      actorId: req.user!.id,
      req
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

const createInviteSchema = z.object({
  email: z.string().email(),
  roleIds: z.array(z.string()).min(1),
  message: z.string().optional(),
});

// NOTE (Phase 1 audit fix — privilege escalation): admin invitation creation
// previously had no permission check beyond the router-level requireAdmin,
// letting any admin-level account invite new admins (including granting
// arbitrary roles via roleIds). Now requires the same permission as the
// equivalent POST /users/invite route above.
router.post('/admin-invitations', requirePermission('users:manage', 'admin:manage'), validateBody(createInviteSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.createAdminInvitation({
      email: req.body.email,
      roleIds: req.body.roleIds,
      message: req.body.message,
      actorId: req.user!.id,
      req
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

const listInvitationsQuerySchema = z.object({
  status: z.string().optional(),
  q: z.string().optional(),
  limit: z.coerce.number().min(1).max(100).optional().default(20),
  cursor: z.string().optional(),
});

router.get('/admin-invitations', requirePermission('users:read', 'admin:read'), async (req: AuthenticatedRequest, res, next) => {
  try {
    const query = listInvitationsQuerySchema.parse(req.query);
    const data = await adminService.listAdminInvitations(query);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

router.post('/admin-invitations/:invitationId/resend', requirePermission('users:manage', 'admin:manage'), async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.resendAdminInvitation({
      invitationId: req.params.invitationId,
      actorId: req.user!.id,
      req
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

router.post('/admin-invitations/:invitationId/revoke', requirePermission('users:manage', 'admin:manage'), async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.revokeAdminInvitation({
      invitationId: req.params.invitationId,
      actorId: req.user!.id,
      req
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;

