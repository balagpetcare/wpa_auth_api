import { Router } from 'express';
import authRoutes from '../modules/auth/auth.routes.js';
import usersRoutes from '../modules/users/users.routes.js';
import adminRoutes, { adminAuthRouter } from '../modules/admin/admin.routes.js';
import communicationRoutes from '../modules/communication/communication.routes.js';
import emailRoutes from '../modules/email/email.routes.js';
import clientsRoutes from '../modules/clients/clients.routes.js';
import rolesRoutes from '../modules/roles/roles.routes.js';
import auditRoutes from '../modules/audit/audit.routes.js';
import oauthRoutes from '../modules/oauth/oauth.routes.js';

const router = Router();

router.get('/health', (_req, res) => {
  res.json({ status: 'UP', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

router.use('/auth', authRoutes);
router.use('/users', usersRoutes);

// Admin auth login is public — mount before the guarded admin router
router.use('/admin/auth', adminAuthRouter);
router.use('/admin/communication', communicationRoutes);
router.use('/admin', emailRoutes);
// All other /admin/* routes require authGuard + admin role (enforced inside adminRoutes)
router.use('/admin', adminRoutes);

router.use('/oauth', oauthRoutes);
router.use('/clients', clientsRoutes);
router.use('/roles', rolesRoutes);
router.use('/audit', auditRoutes);

export default router;
