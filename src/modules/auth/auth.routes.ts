import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '../../middleware/validate.js';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import { loginRateLimit, registerRateLimit, forgotPasswordRateLimit, refreshRateLimit, resetPasswordRateLimit } from '../../middleware/rateLimit.js';
import * as authService from './auth.service.js';
import * as adminService from '../admin/admin.service.js';
import socialRoutes from './social.routes.js';

const router = Router();

router.use('/social', socialRoutes);

// ─── Schemas ─────────────────────────────────────────────────────────────────

const registerSchema = z.object({
  email: z.string().email().optional(),
  phone: z.string().min(7).optional(),
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/).optional(),
  password: z.string().min(8),
  displayName: z.string().max(64).optional(),
  clientId: z.string().optional(),
}).refine((d) => d.email || d.phone || d.username, {
  message: 'At least one of email, phone, or username is required.',
});

const loginSchema = z.object({
  emailOrUsername: z.string().min(1),
  password: z.string().min(1),
  clientId: z.string().optional(),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
});

const logoutSchema = z.object({
  refreshToken: z.string().optional(),
});

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

const resetPasswordSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(8),
});

const verifyEmailRequestSchema = z.object({
  email: z.string().email(),
});

const verifyEmailConfirmSchema = z.object({
  token: z.string().min(1),
});

// ─── Routes ──────────────────────────────────────────────────────────────────

// POST /auth/register
router.post('/register', registerRateLimit, validateBody(registerSchema), async (req, res, next) => {
  try {
    const user = await authService.registerUser(req.body, req);
    res.status(201).json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

// POST /auth/login
router.post('/login', loginRateLimit, validateBody(loginSchema), async (req, res, next) => {
  try {
    const result = await authService.loginUser(req.body, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// POST /auth/refresh
router.post('/refresh', refreshRateLimit, validateBody(refreshSchema), async (req, res, next) => {
  try {
    const result = await authService.refreshTokens(req.body.refreshToken, req);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// POST /auth/logout  (requires valid access token)
router.post('/logout', authGuard, validateBody(logoutSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    await authService.logoutUser(req.user!.id, req.body.refreshToken, req);
    res.json({ success: true, message: 'Logged out successfully.' });
  } catch (err) {
    next(err);
  }
});

// GET /auth/me
router.get('/me', authGuard, async (req: AuthenticatedRequest, res, next) => {
  try {
    const user = await authService.getCurrentUser(req.user!.id);
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

// POST /auth/forgot-password
router.post('/forgot-password', forgotPasswordRateLimit, validateBody(forgotPasswordSchema), async (req, res, next) => {
  try {
    await authService.forgotPassword(req.body.email, req);
    // Always return 200 to avoid user enumeration
    res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
  } catch (err) {
    next(err);
  }
});

// POST /auth/reset-password
router.post('/reset-password', resetPasswordRateLimit, validateBody(resetPasswordSchema), async (req, res, next) => {
  try {
    await authService.resetPassword(req.body.token, req.body.password, req);
    res.json({ success: true, message: 'Password has been reset. Please log in with your new password.' });
  } catch (err) {
    next(err);
  }
});

// POST /auth/verify-email/request  (requires valid access token)
router.post('/verify-email/request', authGuard, validateBody(verifyEmailRequestSchema), async (req: AuthenticatedRequest, res, next) => {
  try {
    await authService.requestEmailVerification(req.user!.id, req.body.email, req);
    res.json({ success: true, message: 'Verification email sent.' });
  } catch (err) {
    next(err);
  }
});

// POST /auth/verify-email/confirm
router.post('/verify-email/confirm', validateBody(verifyEmailConfirmSchema), async (req, res, next) => {
  try {
    await authService.confirmEmailVerification(req.body.token, req);
    res.json({ success: true, message: 'Email verified successfully.' });
  } catch (err) {
    next(err);
  }
});

// ─── Public Admin Invitation Accept / Verify ─────────────────────────────────

const verifyInviteQuerySchema = z.object({
  token: z.string().min(1),
});

router.get('/admin-invitations/verify', async (req, res, next) => {
  try {
    const query = verifyInviteQuerySchema.parse(req.query);
    const data = await adminService.verifyAdminInvitation(query.token);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

const acceptInviteBodySchema = z.object({
  token: z.string().min(1),
  fullName: z.string().max(64).optional(),
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/).optional(),
  password: z.string().min(8),
  confirmPassword: z.string().min(8)
}).refine((d) => d.password === d.confirmPassword, {
  message: 'Passwords do not match.',
  path: ['confirmPassword']
});

router.post('/admin-invitations/accept', validateBody(acceptInviteBodySchema), async (req, res, next) => {
  try {
    const result = await adminService.acceptAdminInvitation({
      token: req.body.token,
      fullName: req.body.fullName,
      username: req.body.username,
      password: req.body.password,
      req
    });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;
