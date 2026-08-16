import { Router } from "express";
import { z } from "zod";
import { validateBody } from "../../middleware/validate.js";
import { authGuard, AuthenticatedRequest } from "../../middleware/auth.js";
import * as authService from "./auth.service.js";
import * as deletionService from "../deletion/deletion.service.js";
import * as adminService from "../admin/admin.service.js";
import socialRoutes from "./social.routes.js";
import identityAuthRoutes from "./identityAuth.routes.js";
import enterpriseAuthRoutes from "./enterpriseAuth.routes.js";
import { enterpriseRateLimit } from "../../lib/antiAbuse.js";
import { avatarUpload } from "../../middleware/upload.js";
import {
  getPublicAvatarUrl,
  uploadAvatarBuffer,
} from "../../lib/avatarStorage.js";

const router = Router();

router.use("/social", socialRoutes);
router.use("/enterprise", enterpriseAuthRoutes);
// Furtail centralized-auth identity foundation: bootstrap config, OTP
// passwordless login, phone+password login, set-password, and the
// Google/Facebook/Apple/Microsoft/Enterprise token-verification login +
// account-linking endpoints. Mounted at the auth router root (not under
// /social) since /bootstrap, /otp/*, /login/phone, /password/set, and
// /identity/* are all top-level per the audit doc, e.g.
// GET /api/v1/auth/bootstrap, POST /api/v1/auth/otp/request,
// POST /api/v1/auth/identity/google.
router.use("/", identityAuthRoutes);

// ─── Schemas ─────────────────────────────────────────────────────────────────

const registerSchema = z
  .object({
    email: z.string().email().optional(),
    phone: z.string().min(7).optional(),
    username: z
      .string()
      .min(3)
      .max(32)
      .regex(/^[a-zA-Z0-9_]+$/)
      .optional(),
    password: z.string().min(8),
    displayName: z.string().max(64).optional(),
    clientId: z.string().optional(),
  })
  .refine((d) => d.email || d.phone || d.username, {
    message: "At least one of email, phone, or username is required.",
  });

const loginSchema = z.object({
  emailOrUsername: z.string().min(1),
  password: z.string().min(1),
  clientId: z.string().optional(),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
  // Optional: lets a session created before the app sent clientId migrate
  // to that client's own audience on rotation (see refreshTokens).
  clientId: z.string().optional(),
});

const logoutSchema = z.object({
  refreshToken: z.string().optional(),
});

const forgotPasswordSchema = z.object({
  email: z.string().email(),
  // Optional: routes the reset-email link to the requesting app's deep link
  // (see PASSWORD_RESET_URL_BY_CLIENT). Absent → admin-panel default.
  clientId: z.string().optional(),
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

const phoneChangeRequestSchema = z.object({
  phone: z.string().min(7).max(32),
});

const phoneChangeConfirmSchema = z.object({
  code: z.string().min(4).max(10),
});

// email/phone are still accepted here (for the first-time-set case only —
// see updateCurrentUserProfile's EMAIL_CHANGE_REQUIRES_VERIFICATION /
// PHONE_CHANGE_REQUIRES_VERIFICATION guard). Changing an already-set,
// verified email/phone must go through /verify-email/* or /phone-change/*.
const updateProfileSchema = z.object({
  displayName: z.string().max(64).nullable().optional(),
  firstName: z.string().max(64).nullable().optional(),
  lastName: z.string().max(64).nullable().optional(),
  dateOfBirth: z.string().nullable().optional(),
  username: z
    .string()
    .min(3)
    .max(32)
    .regex(/^[a-zA-Z0-9_]+$/)
    .nullable()
    .optional(),
  email: z.string().email().nullable().optional(),
  phone: z.string().min(7).max(32).nullable().optional(),
  notificationPreferences: z
    .object({
      securityAlerts: z.boolean().optional(),
      loginAlerts: z.boolean().optional(),
      emailAnnouncements: z.boolean().optional(),
      smsAnnouncements: z.boolean().optional(),
    })
    .optional(),
});

const sessionParamsSchema = z.object({
  sessionId: z.string().min(1),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8),
  confirmPassword: z.string().min(8),
});

const accountConfirmationSchema = z.object({
  password: z.string().min(1).optional(),
});

const accountDeletionRequestSchema = z.object({
  confirm: z.literal(true),
  password: z.string().min(1).optional(),
});

const presenceHeartbeatSchema = z.object({
  clientId: z.string().min(1).optional(),
  appId: z.string().min(1).optional(),
});

// ─── Routes ──────────────────────────────────────────────────────────────────

// POST /auth/register
router.post(
  "/register",
  enterpriseRateLimit({
    route: "auth-register",
    windowMs: 60 * 60 * 1000,
    max: 5,
    identifierFrom: (req) =>
      `${req.body?.email || req.body?.phone || req.body?.username || "unknown"}:${req.ip ?? req.socket.remoteAddress ?? "unknown"}`,
  }),
  validateBody(registerSchema),
  async (req, res, next) => {
    try {
      const user = await authService.registerUser(req.body, req);
      res.status(201).json({ success: true, user });
    } catch (err) {
      next(err);
    }
  },
);

// POST /auth/login
router.post(
  "/login",
  enterpriseRateLimit({
    route: "auth-login",
    windowMs: 15 * 60 * 1000,
    max: 10,
    identifierFrom: (req) =>
      `${req.body?.emailOrUsername ?? ""}:${req.ip ?? ""}`,
    threat: "BOT_TRAFFIC_SPIKE",
    blockScope: "identifier",
  }),
  validateBody(loginSchema),
  async (req, res, next) => {
    try {
      const result = await authService.loginUser(req.body, req);
      res.json({ success: true, ...result });
    } catch (err) {
      next(err);
    }
  },
);

// POST /auth/refresh
router.post(
  "/refresh",
  enterpriseRateLimit({
    route: "auth-refresh",
    windowMs: 15 * 60 * 1000,
    max: 30,
    identifierFrom: (req) => req.body?.refreshToken?.slice?.(0, 16),
  }),
  validateBody(refreshSchema),
  async (req, res, next) => {
    try {
      const result = await authService.refreshTokens(
        req.body.refreshToken,
        req,
        req.body.clientId,
      );
      res.json({ success: true, ...result });
    } catch (err) {
      next(err);
    }
  },
);

// POST /auth/logout  (requires valid access token)
router.post(
  "/logout",
  authGuard,
  validateBody(logoutSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      await authService.logoutUser(req.user!.id, req.body.refreshToken, req);
      res.json({ success: true, message: "Logged out successfully." });
    } catch (err) {
      next(err);
    }
  },
);

// GET /auth/me
router.get("/me", authGuard, async (req: AuthenticatedRequest, res, next) => {
  try {
    const user = await authService.getCurrentUser(req.user!.id);
    res.json({ success: true, user });
  } catch (err) {
    next(err);
  }
});

router.patch(
  "/me",
  authGuard,
  validateBody(updateProfileSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const user = await authService.updateCurrentUserProfile(
        req.user!.id,
        req.body,
        req,
      );
      res.json({ success: true, user });
    } catch (err) {
      next(err);
    }
  },
);

router.post("/me/avatar", authGuard, (req, res, next) => {
  avatarUpload.single("avatar")(req, res, async (error) => {
    if (error) {
      next(error);
      return;
    }
    try {
      const file = (
        req as AuthenticatedRequest & { file?: Express.Multer.File }
      ).file;
      if (!file) {
        throw new Error("Avatar file is required.");
      }
      const key = await uploadAvatarBuffer(file.buffer, file.mimetype);
      const user = await authService.updateCurrentUserAvatar(
        (req as AuthenticatedRequest).user!.id,
        getPublicAvatarUrl(key),
        req,
      );
      res.json({ success: true, user });
    } catch (err) {
      next(err);
    }
  });
});

router.delete(
  "/me/avatar",
  authGuard,
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const user = await authService.removeCurrentUserAvatar(req.user!.id, req);
      res.json({ success: true, user });
    } catch (err) {
      next(err);
    }
  },
);

router.get(
  "/sessions",
  authGuard,
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const sessions = await authService.listMyActiveSessions(
        req.user!.id,
        req.user!.sid,
      );
      res.json({ success: true, sessions });
    } catch (err) {
      next(err);
    }
  },
);

router.delete(
  "/sessions/:sessionId",
  authGuard,
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const params = sessionParamsSchema.parse(req.params);
      const result = await authService.revokeMySession(
        req.user!.id,
        params.sessionId,
        req,
      );
      res.json({ success: true, ...result });
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  "/sessions/logout-others",
  authGuard,
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const result = await authService.logoutAllOtherSessions(
        req.user!.id,
        req.user!.sid,
        req,
      );
      res.json({ success: true, ...result });
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  "/change-password",
  authGuard,
  enterpriseRateLimit({
    route: "auth-change-password",
    windowMs: 15 * 60 * 1000,
    max: 5,
    identifierFrom: (req) => (req as AuthenticatedRequest).user!.id,
    threat: "SUSPICIOUS_ACTIVITY_BLOCKED",
    blockAfter: 8,
    blockTtlMs: 60 * 60 * 1000,
    blockScope: "identifier",
  }),
  validateBody(changePasswordSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const result = await authService.changeCurrentUserPassword(
        req.user!.id,
        req.user!.sid,
        req.body,
        req,
      );
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  "/deactivate",
  authGuard,
  enterpriseRateLimit({
    route: "auth-deactivate-account",
    windowMs: 60 * 60 * 1000,
    max: 3,
    identifierFrom: (req) => (req as AuthenticatedRequest).user!.id,
    threat: "SUSPICIOUS_ACTIVITY_BLOCKED",
    blockAfter: 5,
    blockTtlMs: 60 * 60 * 1000,
    blockScope: "identifier",
  }),
  validateBody(accountConfirmationSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const result = await authService.deactivateCurrentUser(
        req.user!.id,
        req.user!.sid,
        req.body.password,
        req,
      );
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

router.delete(
  "/me",
  authGuard,
  enterpriseRateLimit({
    route: "auth-delete-account",
    windowMs: 60 * 60 * 1000,
    max: 2,
    identifierFrom: (req) => (req as AuthenticatedRequest).user!.id,
    threat: "SUSPICIOUS_ACTIVITY_BLOCKED",
    blockAfter: 4,
    blockTtlMs: 60 * 60 * 1000,
    blockScope: "identifier",
  }),
  validateBody(accountConfirmationSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const result = await authService.deleteCurrentUser(
        req.user!.id,
        req.body.password,
        req,
      );
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  "/deletion/request",
  authGuard,
  enterpriseRateLimit({
    route: "auth-account-deletion-request",
    windowMs: 60 * 60 * 1000,
    max: 3,
    identifierFrom: (req) => (req as AuthenticatedRequest).user!.id,
    threat: "SUSPICIOUS_ACTIVITY_BLOCKED",
    blockAfter: 5,
    blockTtlMs: 60 * 60 * 1000,
    blockScope: "identifier",
  }),
  validateBody(accountDeletionRequestSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const result = await deletionService.requestAuthenticatedAccountDeletion({
        userId: req.user!.id,
        password: req.body.password,
        req,
      });
      res.status(202).json({
        success: true,
        message:
          "Account deletion request received. Use the confirmation code to track status.",
        data: {
          confirmationCode: result.request.confirmationCode,
          requestType: result.request.requestType,
          provider: result.request.provider,
          requestSource: result.request.requestSource,
          status: result.request.status,
          statusUrl: result.statusUrl,
          gracePeriodDeadlineAt: result.request.gracePeriodDeadlineAt,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  "/deletion/:requestId/cancel",
  authGuard,
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const result = await deletionService.cancelDeletionRequestById(
        req.params.requestId,
        req,
      );
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },
);

// POST /auth/forgot-password
router.post(
  "/forgot-password",
  enterpriseRateLimit({
    route: "auth-forgot-password",
    windowMs: 60 * 60 * 1000,
    max: 3,
    identifierFrom: (req) =>
      `${req.body?.email ?? "unknown"}:${req.ip ?? req.socket.remoteAddress ?? "unknown"}`,
    threat: "PASSWORD_RESET_ABUSE",
    blockScope: "identifier",
  }),
  validateBody(forgotPasswordSchema),
  async (req, res, next) => {
    try {
      await authService.forgotPassword(req.body.email, req, req.body.clientId);
      // Always return 200 to avoid user enumeration
      res.json({
        success: true,
        message: "If that email exists, a reset link has been sent.",
      });
    } catch (err) {
      next(err);
    }
  },
);

// POST /auth/reset-password
router.post(
  "/reset-password",
  enterpriseRateLimit({
    route: "auth-reset-password",
    windowMs: 15 * 60 * 1000,
    max: 5,
    identifierFrom: (req) => req.body?.token?.slice?.(0, 16),
    threat: "PASSWORD_RESET_ABUSE",
  }),
  validateBody(resetPasswordSchema),
  async (req, res, next) => {
    try {
      await authService.resetPassword(req.body.token, req.body.password, req);
      res.json({
        success: true,
        message:
          "Password has been reset. Please log in with your new password.",
      });
    } catch (err) {
      next(err);
    }
  },
);

// POST /auth/verify-email/request  (requires valid access token)
router.post(
  "/verify-email/request",
  enterpriseRateLimit({
    route: "auth-verify-email-request",
    windowMs: 60 * 60 * 1000,
    max: 3,
    identifierFrom: (req) =>
      `${req.body?.email ?? "unknown"}:${req.ip ?? req.socket.remoteAddress ?? "unknown"}`,
    threat: "OTP_ABUSE_DETECTED",
    blockScope: "identifier",
  }),
  authGuard,
  validateBody(verifyEmailRequestSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      await authService.requestEmailVerification(
        req.user!.id,
        req.body.email,
        req,
      );
      res.json({ success: true, message: "Verification email sent." });
    } catch (err) {
      next(err);
    }
  },
);

// POST /auth/verify-email/confirm
router.post(
  "/verify-email/confirm",
  enterpriseRateLimit({
    route: "auth-verify-email-confirm",
    windowMs: 15 * 60 * 1000,
    max: 10,
    identifierFrom: (req) => req.body?.token?.slice?.(0, 16),
    threat: "OTP_ABUSE_DETECTED",
  }),
  validateBody(verifyEmailConfirmSchema),
  async (req, res, next) => {
    try {
      await authService.confirmEmailVerification(req.body.token, req);
      res.json({ success: true, message: "Email verified successfully." });
    } catch (err) {
      next(err);
    }
  },
);

// POST /auth/phone-change/request  (requires valid access token) — the only
// supported way to change an already-set phone number; see
// updateCurrentUserProfile's PHONE_CHANGE_REQUIRES_VERIFICATION guard.
router.post(
  "/phone-change/request",
  enterpriseRateLimit({
    route: "auth-phone-change-request",
    windowMs: 60 * 60 * 1000,
    max: 5,
    identifierFrom: (req) =>
      `${req.body?.phone ?? "unknown"}:${req.ip ?? req.socket.remoteAddress ?? "unknown"}`,
    threat: "OTP_ABUSE_DETECTED",
    blockScope: "identifier",
  }),
  authGuard,
  validateBody(phoneChangeRequestSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const devCode = await authService.requestPhoneChange(
        req.user!.id,
        req.body.phone,
        req,
      );
      res.json({
        success: true,
        message: "Verification code sent.",
        ...(devCode ? { devCode } : {}),
      });
    } catch (err) {
      next(err);
    }
  },
);

// POST /auth/phone-change/confirm  (requires valid access token)
router.post(
  "/phone-change/confirm",
  enterpriseRateLimit({
    route: "auth-phone-change-confirm",
    windowMs: 15 * 60 * 1000,
    max: 10,
    identifierFrom: (req) => (req as AuthenticatedRequest).user?.sub,
    threat: "OTP_ABUSE_DETECTED",
  }),
  authGuard,
  validateBody(phoneChangeConfirmSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      await authService.confirmPhoneChange(req.user!.id, req.body.code, req);
      res.json({ success: true, message: "Phone verified successfully." });
    } catch (err) {
      next(err);
    }
  },
);

// POST /auth/presence/heartbeat
router.post(
  "/presence/heartbeat",
  authGuard,
  enterpriseRateLimit({
    route: "auth-presence-heartbeat",
    windowMs: 5 * 60 * 1000,
    max: 12,
    identifierFrom: (req) => (req as AuthenticatedRequest).user?.sub,
  }),
  validateBody(presenceHeartbeatSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const result = await authService.heartbeatPresence(
        req.user!.id,
        req.body.appId ?? req.body.clientId ?? null,
      );
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },
);

// ─── Public Admin Invitation Accept / Verify ─────────────────────────────────

const verifyInviteQuerySchema = z.object({
  token: z.string().min(1),
});

router.get("/admin-invitations/verify", async (req, res, next) => {
  try {
    const query = verifyInviteQuerySchema.parse(req.query);
    const data = await adminService.verifyAdminInvitation(query.token);
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

const acceptInviteBodySchema = z
  .object({
    token: z.string().min(1),
    fullName: z.string().max(64).optional(),
    username: z
      .string()
      .min(3)
      .max(32)
      .regex(/^[a-zA-Z0-9_]+$/)
      .optional(),
    password: z.string().min(8),
    confirmPassword: z.string().min(8),
  })
  .refine((d) => d.password === d.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
  });

router.post(
  "/admin-invitations/accept",
  validateBody(acceptInviteBodySchema),
  async (req, res, next) => {
    try {
      const result = await adminService.acceptAdminInvitation({
        token: req.body.token,
        fullName: req.body.fullName,
        username: req.body.username,
        password: req.body.password,
        req,
      });
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

export default router;
