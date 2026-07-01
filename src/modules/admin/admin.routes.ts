import { Router } from 'express';
import { z } from 'zod';
import { UserStatus, AuthClientStatus, AuthClientType, OAuthProvider, AdminNotificationCategory, AdminNotificationSeverity } from '@prisma/client';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import { requireAdmin } from '../../middleware/requireRole.js';
import { validateBody } from '../../middleware/validate.js';
import { parsePagination, paginatedResponse } from '../../lib/pagination.js';
import * as adminService from './admin.service.js';
import * as authService from '../auth/auth.service.js';
import { loginRateLimit } from '../../middleware/rateLimit.js';
import { avatarUpload } from '../../middleware/upload.js';
import { AppError } from '../../lib/errors.js';

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

adminAuthRouter.post('/login', loginRateLimit, validateBody(adminLoginSchema), async (req, res, next) => {
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

adminAuthRouter.post('/logout', authGuard, requireAdmin, validateBody(z.object({ refreshToken: z.string().optional() })), async (req: AuthenticatedRequest, res, next) => {
  try {
    await authService.logoutUser(req.user!.id, req.body.refreshToken, req);
    res.json({ success: true, message: 'Logged out successfully.' });
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
  emailVerified: z.enum(['true', 'false', 'all']).optional(),
  phoneVerified: z.enum(['true', 'false', 'all']).optional(),
  hasOAuth: z.enum(['true', 'false', 'all']).optional(),
  provider: z.nativeEnum(OAuthProvider).optional(),
  createdFrom: z.string().datetime().optional(),
  createdTo: z.string().datetime().optional(),
  lastLoginFrom: z.string().datetime().optional(),
  lastLoginTo: z.string().datetime().optional(),
  sortBy: z.enum(['createdAt', 'lastLoginAt', 'email', 'username', 'status']).optional(),
  sortOrder: z.enum(['asc', 'desc']).optional(),
  limit: z.coerce.number().min(1).max(100).optional().default(50),
  cursor: z.string().optional(),
  page: z.coerce.number().min(1).optional(),
  includeCount: z.enum(['true', 'false']).optional()
});

// GET /admin/users/summary
router.get('/users/summary', async (req, res, next) => {
  try {
    const summary = await adminService.getUsersSummary();
    res.json({ success: true, summary });
  } catch (err) {
    next(err);
  }
});

// GET /admin/users
router.get('/users', async (req, res, next) => {
  try {
    const query = usersQuerySchema.parse(req.query);
    
    const data = await adminService.listUsers({
      search: query.q,
      status: query.status as UserStatus | 'ALL',
      role: query.role,
      emailVerified: query.emailVerified,
      phoneVerified: query.phoneVerified,
      hasOAuth: query.hasOAuth,
      provider: query.provider,
      createdFrom: query.createdFrom ? new Date(query.createdFrom) : undefined,
      createdTo: query.createdTo ? new Date(query.createdTo) : undefined,
      lastLoginFrom: query.lastLoginFrom ? new Date(query.lastLoginFrom) : undefined,
      lastLoginTo: query.lastLoginTo ? new Date(query.lastLoginTo) : undefined,
      sortBy: query.sortBy,
      sortOrder: query.sortOrder,
      limit: query.limit,
      cursor: query.cursor,
      page: query.page,
      includeCount: query.includeCount === 'true'
    });
    
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

// GET /admin/users/:id
router.get('/users/:id', async (req, res, next) => {
  try {
    const user = await adminService.getUserById((req.params.id as string));
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/users/:id/status
router.patch('/users/:id/status', validateBody(z.object({ status: z.nativeEnum(UserStatus) })), async (req: AuthenticatedRequest, res, next) => {
  try {
    const user = await adminService.updateUserStatus((req.params.id as string), req.body.status, req.user!.id, req);
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/users/:id
router.patch('/users/:id', validateBody(z.object({
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
router.delete('/users/:id', async (req: AuthenticatedRequest, res, next) => {
  try {
    const user = await adminService.deleteUserAccount(req.params.id, req.user!.id, req);
    res.json({ success: true, message: 'User account deactivated safely.', user });
  } catch (err) {
    next(err);
  }
});

// POST /admin/users/:id/reset-password
router.post('/users/:id/reset-password', async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.resetUserPasswordAdmin(req.params.id, req.user!.id, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// POST /admin/users/:id/revoke-sessions
router.post('/users/:id/revoke-sessions', async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.revokeUserSessions(req.params.id, req.user!.id, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// GET /admin/users/:id/sessions
router.get('/users/:id/sessions', async (req, res, next) => {
  try {
    const sessions = await adminService.getUserSessions((req.params.id as string));
    res.json({ success: true, sessions });
  } catch (err) {
    next(err);
  }
});

// GET /admin/users/:id/audit-logs
router.get('/users/:id/audit-logs', async (req, res, next) => {
  try {
    const pagination = parsePagination(req);
    const { logs, total } = await adminService.getUserAuditLogs((req.params.id as string), pagination);
    res.json({ success: true, ...paginatedResponse(logs, total, pagination) });
  } catch (err) {
    next(err);
  }
});

// â”€â”€â”€ Roles & Permissions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// GET /admin/roles
router.get('/roles', async (_req, res, next) => {
  try {
    const roles = await adminService.listRoles();
    res.json({ success: true, roles });
  } catch (err) {
    next(err);
  }
});

// POST /admin/roles
router.post('/roles', validateBody(z.object({
  name: z.string().min(2),
  description: z.string().optional(),
})), async (_req, res, next) => {
  try {
    const role = await adminService.createRole(_req.body);
    res.status(201).json({ success: true, role });
  } catch (err) {
    next(err);
  }
});

// PATCH /admin/roles/:id
router.patch('/roles/:id', validateBody(z.object({
  name: z.string().min(2).optional(),
  description: z.string().optional(),
})), async (req, res, next) => {
  try {
    const role = await adminService.updateRole((req.params.id as string), req.body);
    res.json({ success: true, role });
  } catch (err) {
    next(err);
  }
});

// GET /admin/permissions
router.get('/permissions', async (_req, res, next) => {
  try {
    const permissions = await adminService.listPermissions();
    res.json({ success: true, permissions });
  } catch (err) {
    next(err);
  }
});

// POST /admin/users/:id/roles
router.post('/users/:id/roles', validateBody(z.object({ roleId: z.string().min(1) })), async (req: AuthenticatedRequest, res, next) => {
  try {
    await adminService.assignRoleToUser((req.params.id as string), req.body.roleId, req.user!.id, req);
    res.json({ success: true, message: 'Role assigned.' });
  } catch (err) {
    next(err);
  }
});

// DELETE /admin/users/:id/roles/:roleId
router.delete('/users/:id/roles/:roleId', async (req: AuthenticatedRequest, res, next) => {
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
    const pagination = parsePagination(req);
    const userId = req.query['userId'] as string | undefined;
    const action = req.query['action'] as string | undefined;
    const { logs, total } = await adminService.listAuditLogs({ userId, action, pagination });
    res.json({ success: true, ...paginatedResponse(logs, total, pagination) });
  } catch (err) {
    next(err);
  }
});

// GET /admin/security-events
router.get('/security-events', async (req, res, next) => {
  try {
    const pagination = parsePagination(req);
    const userId = req.query['userId'] as string | undefined;
    const resolvedParam = req.query['resolved'] as string | undefined;
    const resolved = resolvedParam === 'true' ? true : resolvedParam === 'false' ? false : undefined;
    const { events, total } = await adminService.listSecurityEvents({ userId, resolved, pagination });
    res.json({ success: true, ...paginatedResponse(events, total, pagination) });
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

// PATCH /admin/social-providers/:provider
router.patch('/social-providers/:provider', validateBody(z.object({
  enabled: z.boolean().optional(),
  displayOrder: z.number().int().optional(),
  displayName: z.string().optional(),
})), async (req, res, next) => {
  try {
    const provider = await adminService.updateSocialProvider((req.params.provider as string), req.body);
    res.json({ success: true, provider });
  } catch (err) {
    next(err);
  }
});

// ─── Global Sessions ────────────────────────────────────────────────────────
router.get('/sessions', async (req, res, next) => {
  try {
    const pagination = parsePagination(req);
    const search = req.query['search'] as string | undefined;
    const status = req.query['status'] as string | undefined;
    const userId = req.query['userId'] as string | undefined;
    const { sessions, total } = await adminService.listGlobalSessions({ search, status, userId, pagination });
    res.json({ success: true, ...paginatedResponse(sessions, total, pagination) });
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

// ─── User Actions ───────────────────────────────────────────────────────────
router.post('/users/:id/reset-password', async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.triggerPasswordReset(req.params.id, req.user!.id, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// ─── My Account ───────────────────────────────────────────────────────────────
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
      const avatarUrl = adminService.buildAvatarPublicUrl(file.filename);
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

router.post('/account/change-password', async (req: AuthenticatedRequest, res, next) => {
  try {
    const result = await adminService.changeMyPassword(req.user!.id, req.body, req);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

const notificationsQuerySchema = z.object({
  status: z.enum(['unread', 'read', 'all']).optional().default('all'),
  category: z.nativeEnum(AdminNotificationCategory).optional(),
  severity: z.nativeEnum(AdminNotificationSeverity).optional(),
  limit: z.coerce.number().min(1).max(50).optional().default(20),
  cursor: z.string().optional(),
});

router.get('/notifications', async (req: AuthenticatedRequest, res, next) => {
  try {
    const query = notificationsQuerySchema.parse(req.query);
    const data = await adminService.listMyNotifications({
      userId: req.user!.id,
      status: query.status,
      category: query.category,
      severity: query.severity,
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

router.patch('/notifications/:notificationId/read', async (req: AuthenticatedRequest, res, next) => {
  try {
    const notification = await adminService.markNotificationRead(req.user!.id, req.params.notificationId);
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

const adminUsersQuerySchema = z.object({
  q: z.string().optional(),
  role: z.string().optional(),
  status: z.string().optional(),
  limit: z.coerce.number().min(1).max(100).optional().default(20),
  cursor: z.string().optional(),
});

router.get('/admin-users', async (req: AuthenticatedRequest, res, next) => {
  try {
    const query = adminUsersQuerySchema.parse(req.query);
    const data = await adminService.listAdminUsers(query);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

const assignExistingSchema = z.object({
  userId: z.string().min(1),
  roleIds: z.array(z.string()),
});

router.post('/admin-users/assign-existing', validateBody(assignExistingSchema), async (req: AuthenticatedRequest, res, next) => {
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

router.post('/admin-invitations', validateBody(createInviteSchema), async (req: AuthenticatedRequest, res, next) => {
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

router.get('/admin-invitations', async (req: AuthenticatedRequest, res, next) => {
  try {
    const query = listInvitationsQuerySchema.parse(req.query);
    const data = await adminService.listAdminInvitations(query);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

router.post('/admin-invitations/:invitationId/resend', async (req: AuthenticatedRequest, res, next) => {
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

router.post('/admin-invitations/:invitationId/revoke', async (req: AuthenticatedRequest, res, next) => {
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

