import bcrypt from "bcrypt";
import { randomBytes } from "crypto";
import { UserStatus } from "@prisma/client";
import { prisma } from "../../lib/db.js";
import { config } from "../../config/index.js";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  hashToken,
  generateOpaqueToken,
  parseTtlToSeconds,
} from "../../lib/tokens.js";
import { AppError, ErrorCodes } from "../../lib/errors.js";
import { writeAuditLog, writeSecurityEvent } from "../../lib/audit.js";
import {
  getServiceAdminPermissions,
  adminAudiencesForPermissions,
} from "../../lib/adminAccess.js";
import { createAdminNotification } from "../../lib/adminNotifications.js";
import { sendEmail } from "../../lib/mailer.js";
import {
  sendTemplatedEmail,
  sendTemplatedEmailWithFallback,
} from "../../lib/sendTemplatedEmail.js";
import {
  sendLoginAlertEmail,
  sendWelcomeEmail,
} from "../../lib/emailNotifications.js";
import { sendOtpSms } from "../communication/communication.service.js";
import { Request } from "express";
import {
  logAbuseSignal,
  clearRisk,
  clearLoginAbuseState,
} from "../../lib/antiAbuse.js";
import { recordPresenceHeartbeat } from "../../lib/presence.js";
import { incrementMetric } from "../../lib/metrics.js";
import { removeAvatarByUrl } from "../../lib/avatarStorage.js";
import { buildActionLink } from "./resetLinkRouting.js";

export const BCRYPT_ROUNDS = 12;

/**
 * Builds an auth-email action link (password reset / email verification),
 * routing per requesting client when configured.
 *
 * Historically these links hardcoded `${ADMIN_PANEL_ORIGIN}/auth/user/...`,
 * which is right for the admin panel but wrong for mobile app users (their
 * email link opened the admin web app instead of deep-linking into Furtail/
 * BPA). This resolves a per-client base URL from a JSON env map
 * (PASSWORD_RESET_URL_BY_CLIENT / EMAIL_VERIFICATION_URL_BY_CLIENT). When the
 * request carries a clientId present in the map, that base wins and the token
 * is appended as `?token=...`. Otherwise the admin-panel default is used
 * unchanged, so the admin panel's own reset/verify flow is never broken.
 */
export function buildPasswordResetLink(
  token: string,
  clientId?: string | null,
): string {
  return buildActionLink(
    config.PASSWORD_RESET_URL_BY_CLIENT,
    clientId,
    token,
    `${config.ADMIN_PANEL_ORIGIN}/auth/user/reset-password`,
  );
}

export function buildEmailVerificationLink(
  token: string,
  clientId?: string | null,
): string {
  return buildActionLink(
    config.EMAIL_VERIFICATION_URL_BY_CLIENT,
    clientId,
    token,
    `${config.ADMIN_PANEL_ORIGIN}/auth/user/verify-email`,
  );
}

export type SafeUser = {
  id: string;
  email: string | null;
  phone: string | null;
  username: string | null;
  displayName: string | null;
  firstName: string | null;
  lastName: string | null;
  dateOfBirth: string | null;
  avatarUrl: string | null;
  status: UserStatus;
  emailVerifiedAt: Date | null;
  phoneVerifiedAt: Date | null;
  notificationPreferences: {
    securityAlerts: boolean;
    loginAlerts: boolean;
    emailAnnouncements: boolean;
    smsAnnouncements: boolean;
  };
  roles: string[];
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
  lastPasswordChangedAt?: Date | null;
};

const DEFAULT_NOTIFICATION_PREFERENCES = {
  securityAlerts: true,
  loginAlerts: true,
  emailAnnouncements: false,
  smsAnnouncements: false,
} as const;

function normalizeNotificationPreferences(
  value: unknown,
): SafeUser["notificationPreferences"] {
  const source =
    value && typeof value === "object"
      ? (value as Record<string, unknown>)
      : {};
  return {
    securityAlerts:
      source["securityAlerts"] === undefined
        ? DEFAULT_NOTIFICATION_PREFERENCES.securityAlerts
        : Boolean(source["securityAlerts"]),
    loginAlerts:
      source["loginAlerts"] === undefined
        ? DEFAULT_NOTIFICATION_PREFERENCES.loginAlerts
        : Boolean(source["loginAlerts"]),
    emailAnnouncements:
      source["emailAnnouncements"] === undefined
        ? DEFAULT_NOTIFICATION_PREFERENCES.emailAnnouncements
        : Boolean(source["emailAnnouncements"]),
    smsAnnouncements:
      source["smsAnnouncements"] === undefined
        ? DEFAULT_NOTIFICATION_PREFERENCES.smsAnnouncements
        : Boolean(source["smsAnnouncements"]),
  };
}

function safeUser(user: any, roles: string[] = []): SafeUser {
  return {
    id: user.id,
    email: user.email,
    phone: user.phone,
    username: user.username,
    displayName: user.displayName,
    firstName: user.firstName ?? null,
    lastName: user.lastName ?? null,
    // Date-only (no time-of-day component): serialize as YYYY-MM-DD so
    // clients never have to worry about timezone-shifting a DOB across
    // midnight. Never included in any public/visitor-facing payload — this
    // type is only used for the authenticated user's own /auth/me response.
    dateOfBirth: user.dateOfBirth
      ? new Date(user.dateOfBirth).toISOString().slice(0, 10)
      : null,
    avatarUrl: user.avatarUrl,
    status: user.status,
    emailVerifiedAt: user.emailVerifiedAt,
    phoneVerifiedAt: user.phoneVerifiedAt,
    notificationPreferences: normalizeNotificationPreferences(
      user.notificationPreferences,
    ),
    roles,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    lastLoginAt: user.lastLoginAt,
    lastPasswordChangedAt: user.lastPasswordChangedAt ?? null,
  };
}

async function getUserRoles(userId: string): Promise<string[]> {
  const userRoles = await prisma.userRole.findMany({
    where: { userId },
    include: { role: true },
  });
  return userRoles.map((ur) => ur.role.name);
}

export async function resolveClient(clientId?: string, req?: Request) {
  if (!clientId) return null;
  const client = await prisma.authClient.findUnique({ where: { clientId } });
  if (!client || client.status !== "ACTIVE") return null;

  if (req && req.headers.origin) {
    const origin = req.headers.origin;
    if (
      !client.allowedOrigins.includes(origin) &&
      !client.allowedOrigins.includes("*")
    ) {
      console.warn(
        `[SECURITY] Blocked invalid origin "${origin}" for client "${client.id}" in auth flow`,
      );
      await writeSecurityEvent({
        type: "SUSPICIOUS_OAUTH",
        severity: "MEDIUM",
        metadata: { reason: "invalid_origin", origin, clientId: client.id },
        req,
      });
      throw new AppError(
        "Origin not allowed for this client.",
        "INVALID_ORIGIN",
        403,
      );
    }
  }

  return client;
}

function buildTokenExpiry(ttl: string): Date {
  return new Date(Date.now() + parseTtlToSeconds(ttl) * 1000);
}

// ─── Register ────────────────────────────────────────────────────────────────

export async function registerUser(
  opts: {
    email?: string;
    phone?: string;
    username?: string;
    password: string;
    displayName?: string;
    clientId?: string;
  },
  req: Request,
) {
  if (!opts.email && !opts.phone && !opts.username) {
    throw new AppError(
      "Provide at least one of email, phone, or username.",
      "MISSING_IDENTIFIER",
    );
  }

  const existing = await prisma.user.findFirst({
    where: {
      OR: [
        opts.email ? { email: opts.email } : undefined,
        opts.phone ? { phone: opts.phone } : undefined,
        opts.username ? { username: opts.username } : undefined,
      ].filter(Boolean) as any[],
    },
  });
  if (existing)
    throw new AppError(
      "An account with those credentials already exists.",
      "ALREADY_EXISTS",
      409,
    );

  const passwordHash = await bcrypt.hash(opts.password, BCRYPT_ROUNDS);
  const client = await resolveClient(opts.clientId, req);

  const user = await prisma.user.create({
    data: {
      email: opts.email,
      phone: opts.phone,
      username: opts.username,
      passwordHash,
      displayName: opts.displayName,
      status: UserStatus.PENDING_VERIFICATION,
    },
  });

  // Assign default user role
  const defaultRole = await prisma.role.findFirst({
    where: { name: { in: ["user", "USER"] } },
  });
  if (defaultRole) {
    await prisma.userRole.create({
      data: { userId: user.id, roleId: defaultRole.id },
    });
  }

  if (client) {
    await prisma.userClientAccess.upsert({
      where: { userId_clientId: { userId: user.id, clientId: client.id } },
      update: {},
      create: { userId: user.id, clientId: client.id, status: "ACTIVE" },
    });
  }

  await writeAuditLog({
    userId: user.id,
    clientId: client?.id,
    action: "REGISTER",
    req,
  });

  if (opts.email) {
    try {
      const token = generateOpaqueToken(32);
      const tokenHash = hashToken(token);
      await prisma.emailVerificationToken.create({
        data: {
          userId: user.id,
          email: opts.email,
          tokenHash,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        },
      });
      // Phase 2.5 incidental fix (docs/phase-2-5-public-auth-rs256-oidc.md):
      // this pointed at config.APP_URL, which is this API server's own base
      // URL (http://localhost:5010 by default) — not a frontend page, so
      // the link in every verification email 404'd. ADMIN_PANEL_ORIGIN is
      // the Next.js frontend that now hosts the real public verify-email
      // page at /auth/user/verify-email.
      const verificationLink = buildEmailVerificationLink(token, opts.clientId ?? null);
      await sendTemplatedEmailWithFallback(
        {
          templateKey: "email_verification",
          purpose: "REGISTER",
          variables: {
            userName: opts.displayName || opts.email,
            verificationLink,
            expiresIn: "24 hours",
          },
          to: opts.email,
          userId: user.id,
          clientId: client?.id || null,
          req,
        },
        "Welcome! Please verify your email",
        `Please verify your email by clicking this link: ${verificationLink}`,
      );
    } catch (e) {
      console.error("Failed to send registration verification email", e);
    }
  }

  return safeUser(user, defaultRole ? ["user"] : []);
}

// ─── Login ───────────────────────────────────────────────────────────────────

export async function loginUser(
  opts: { emailOrUsername: string; password: string; clientId?: string },
  req: Request,
) {
  const identifier = opts.emailOrUsername.trim().toLowerCase();
  const loginAbuseIdentifier = `${identifier}:${req.ip ?? req.socket.remoteAddress ?? "unknown"}`;
  const isEmail = identifier.includes("@");

  const user = await prisma.user.findFirst({
    where: isEmail
      ? { email: identifier }
      : {
          OR: [
            { username: identifier },
            { email: identifier },
            { phone: identifier },
          ],
        },
  });

  if (!user || !user.passwordHash) {
    incrementMetric("login_failure_total");
    await logAbuseSignal({
      route: "auth-login",
      req,
      identifier: loginAbuseIdentifier,
      threat: "BOT_TRAFFIC_SPIKE",
      blockAfter: 6,
      blockTtlMs: 30 * 60 * 1000,
    });
    throw new AppError("Invalid credentials.", "INVALID_CREDENTIALS", 401);
  }

  const valid = await bcrypt.compare(opts.password, user.passwordHash);
  if (!valid) {
    incrementMetric("login_failure_total");
    await writeAuditLog({
      userId: user.id,
      action: "LOGIN",
      metadata: { success: false },
      req,
    });

    // Check failed login attempts threshold (Requirement 2 & 11)
    try {
      const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
      const recentLoginAudits = await prisma.auditLog.findMany({
        where: {
          userId: user.id,
          action: "LOGIN",
          createdAt: { gte: fifteenMinutesAgo },
        },
        take: 6,
        orderBy: { createdAt: "desc" },
      });
      const failedCount = recentLoginAudits.filter((log) => {
        const meta = log.metadata as any;
        return meta && meta.success === false;
      }).length;

      if (failedCount >= 5) {
        await createAdminNotification({
          userId: user.id,
          type: "MULTIPLE_FAILED_LOGINS",
          title: "Multiple failed login attempts",
          message: `Multiple failed login attempts (${failedCount}) were detected for your account.`,
          severity: "CRITICAL",
          category: "SECURITY",
          actionUrl: "/security-events",
        });
      }
    } catch (err) {
      console.error("Failed to process failed login threshold:", err);
    }

    await logAbuseSignal({
      route: "auth-login",
      req,
      identifier: loginAbuseIdentifier,
      userId: user.id,
      threat: "BOT_TRAFFIC_SPIKE",
      blockAfter: 6,
      blockTtlMs: 30 * 60 * 1000,
    });
    throw new AppError("Invalid credentials.", "INVALID_CREDENTIALS", 401);
  }

  if (user.status === UserStatus.SUSPENDED) {
    throw new AppError(
      "Your account has been suspended.",
      "ACCOUNT_SUSPENDED",
      403,
    );
  }
  if (user.status === UserStatus.DELETED) {
    throw new AppError("Invalid credentials.", "INVALID_CREDENTIALS", 401);
  }

  const client = await resolveClient(opts.clientId, req);
  if (client) {
    await prisma.userClientAccess.upsert({
      where: { userId_clientId: { userId: user.id, clientId: client.id } },
      update: {},
      create: { userId: user.id, clientId: client.id, status: "ACTIVE" },
    });
  }

  const session = await prisma.loginSession.create({
    data: {
      userId: user.id,
      clientId: client?.id ?? (await getOrCreateInternalClientId()),
      sessionToken: generateOpaqueToken(),
      expiresAt: buildTokenExpiry(config.REFRESH_TOKEN_TTL),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers["user-agent"],
    },
  });

  const roles = await getUserRoles(user.id);
  const audience = client?.audience ?? undefined;
  const servicePerms = await getServiceAdminPermissions(user.id);
  const adminAudiences = adminAudiencesForPermissions(servicePerms);
  // Only Global Super Admin-style principals (non-empty servicePerms) get
  // extra audiences appended; every other login's token is byte-identical
  // to before this change.
  const accessAudience =
    adminAudiences.length > 0
      ? Array.from(
          new Set([
            audience ?? config.ACCESS_TOKEN_AUDIENCE,
            ...adminAudiences,
          ]),
        )
      : audience;
  const accessToken = signAccessToken(
    {
      sub: user.id,
      email: user.email,
      username: user.username,
      roles,
      sid: session.id,
      ...(servicePerms.length > 0 ? { perms: servicePerms } : {}),
    },
    accessAudience,
  );
  const refreshToken = signRefreshToken(user.id, audience);
  const tokenHash = hashToken(refreshToken);

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId: client?.id ?? (await getOrCreateInternalClientId()),
      tokenHash,
      scopes: ["openid", "offline_access"],
      expiresAt: buildTokenExpiry(config.REFRESH_TOKEN_TTL),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers["user-agent"],
      familyId: session.id,
    },
  });

  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() },
  });

  await writeAuditLog({
    userId: user.id,
    clientId: client?.id,
    action: "LOGIN",
    metadata: { success: true },
    req,
  });
  incrementMetric("login_success_total");
  await clearRisk({ req, identifier });
  await clearLoginAbuseState({ req, identifier: loginAbuseIdentifier });

  // Sensitive/security login checks (Requirement 2 & 11)
  try {
    const previousSession = await prisma.loginSession.findFirst({
      where: {
        userId: user.id,
        NOT: { id: session.id },
      },
      orderBy: { createdAt: "desc" },
    });

    if (previousSession) {
      if (
        session.ipAddress &&
        previousSession.ipAddress &&
        session.ipAddress !== previousSession.ipAddress
      ) {
        await createAdminNotification({
          userId: user.id,
          type: "NEW_IP_LOGIN",
          title: "New IP login detected",
          message: `A login was recorded from a new IP address: ${session.ipAddress}.`,
          severity: "WARNING",
          category: "SECURITY",
          actionUrl: "/sessions",
        });
      }

      if (
        session.userAgent &&
        previousSession.userAgent &&
        session.userAgent !== previousSession.userAgent
      ) {
        await createAdminNotification({
          userId: user.id,
          type: "NEW_DEVICE_LOGIN",
          title: "New device login detected",
          message: `A login was recorded from a new device or browser.`,
          severity: "WARNING",
          category: "SECURITY",
          actionUrl: "/sessions",
        });
      }

      if (
        session.country &&
        previousSession.country &&
        session.country !== previousSession.country
      ) {
        await createAdminNotification({
          userId: user.id,
          type: "UNUSUAL_LOCATION_LOGIN",
          title: "Unusual location login detected",
          message: `A login was recorded from a different country: ${session.country}.`,
          severity: "CRITICAL",
          category: "SECURITY",
          actionUrl: "/sessions",
        });
      }
    }
  } catch (err) {
    console.error("Failed to process sensitive login checks:", err);
  }

  // Send login alert email
  if (user.email) {
    try {
      await sendLoginAlertEmail(
        user.email,
        user.displayName || user.email,
        req.ip ?? req.socket.remoteAddress?.toString() ?? null,
        req.headers["user-agent"]?.toString() ?? null,
        user.id,
        client?.id || null,
      );
    } catch (e) {
      console.error("Failed to send login alert email", e);
    }
  }

  return {
    accessToken,
    refreshToken,
    expiresIn: parseTtlToSeconds(config.ACCESS_TOKEN_TTL),
    user: safeUser(user, roles),
  };
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

export async function revokeSessionFamily(
  userId: string,
  familyId: string,
  reason: string,
) {
  // Revoke all refresh tokens in the family
  await prisma.refreshToken.updateMany({
    where: { familyId, userId, revokedAt: null },
    data: {
      revokedAt: new Date(),
      revocationReason: reason,
    },
  });

  // Revoke the related LoginSession
  await prisma.loginSession.updateMany({
    where: { id: familyId, userId, revokedAt: null },
    data: {
      revokedAt: new Date(),
      revocationReason: reason,
    },
  });
}

export async function refreshTokens(
  rawRefreshToken: string,
  req: Request,
  requestedClientId?: string,
) {
  let payload: { sub: string };
  try {
    payload = verifyRefreshToken(rawRefreshToken);
  } catch {
    throw new AppError(
      "Invalid or expired refresh token.",
      "TOKEN_INVALID",
      401,
    );
  }

  const tokenHash = hashToken(rawRefreshToken);
  const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });

  if (!stored) {
    throw new AppError(
      "Refresh token is invalid or has been revoked.",
      "TOKEN_REVOKED",
      401,
    );
  }

  // Reuse detection:
  if (stored.revokedAt || stored.expiresAt < new Date()) {
    if (stored.revokedAt && stored.revocationReason === "ROTATED") {
      // Reused a rotated token!
      if (!stored.reusedAt) {
        // Mark as reused to prevent duplicate processing
        await prisma.refreshToken.update({
          where: { id: stored.id },
          data: { reusedAt: new Date() },
        });

        // Revoke the session family
        if (stored.familyId) {
          await revokeSessionFamily(
            stored.userId,
            stored.familyId,
            "REUSE_DETECTED",
          );
        }

        // Increase abuse risk score for IP
        await logAbuseSignal({
          route: "auth-refresh",
          req,
          identifier: rawRefreshToken.slice(0, 16),
          threat: "REFRESH_TOKEN_REUSE_DETECTED",
          blockAfter: 3,
        });
        incrementMetric("refresh_token_reuse_total");

        // Write SecurityEvent
        await writeSecurityEvent({
          type: "TOKEN_REUSE_DETECTED",
          severity: "HIGH",
          metadata: {
            userId: stored.userId,
            clientId: stored.clientId,
            familyId: stored.familyId,
            ipAddress: req.ip ?? req.socket.remoteAddress,
            userAgent: req.headers["user-agent"],
          },
          req,
        });

        // Create AdminNotification/security notification
        await createAdminNotification({
          userId: stored.userId,
          type: "REFRESH_TOKEN_REUSE_DETECTED",
          title: "Potential refresh token theft detected",
          message: `Refresh token reuse detected for user ${stored.userId}. Entire session family has been revoked.`,
          severity: "CRITICAL",
          category: "SECURITY",
          metadata: {
            userId: stored.userId,
            clientId: stored.clientId,
            familyId: stored.familyId,
          },
        });
      }

      throw new AppError(
        "Refresh token reuse detected.",
        ErrorCodes.REFRESH_TOKEN_REUSED,
        401,
      );
    }

    // Normal invalid/revoked/expired token
    await logAbuseSignal({
      route: "auth-refresh",
      req,
      identifier: rawRefreshToken.slice(0, 16),
      threat: "SUSPICIOUS_ACTIVITY_BLOCKED",
      blockAfter: 8,
    });
    throw new AppError(
      "Refresh token is invalid or has been revoked.",
      "TOKEN_REVOKED",
      401,
    );
  }

  if (stored.userId !== payload.sub) {
    throw new AppError("Token mismatch.", "TOKEN_INVALID", 401);
  }

  const user = await prisma.user.findUnique({ where: { id: payload.sub } });
  if (
    !user ||
    user.status === UserStatus.DELETED ||
    user.status === UserStatus.SUSPENDED
  ) {
    throw new AppError("User is not active.", "ACCOUNT_INACTIVE", 403);
  }

  // Verify that the login session is not revoked
  if (stored.familyId) {
    const session = await prisma.loginSession.findUnique({
      where: { id: stored.familyId },
    });
    if (!session || session.revokedAt) {
      // The session family is already revoked, so we should revoke this token too
      await prisma.refreshToken.update({
        where: { id: stored.id },
        data: { revokedAt: new Date(), revocationReason: "SESSION_REVOKED" },
      });
      throw new AppError(
        "Session is invalid or has been revoked.",
        ErrorCodes.SESSION_REVOKED,
        401,
      );
    }
  }

  const tokenClient = await prisma.authClient.findUnique({
    where: { id: stored.clientId },
    select: { audience: true },
  });
  let audience = tokenClient?.audience ?? undefined;
  let effectiveClientDbId = stored.clientId;

  // Controlled audience migration: a session created before the app sent
  // clientId is bound to the internal default client (audience null →
  // global default, e.g. "bpa-mobile"). When the refresh request now names
  // a real client, rebind the session to it so the rotated tokens carry the
  // app's own audience (e.g. "furtail-mobile"). Only sessions on the
  // internal/default client are eligible — a session already bound to a
  // real client can NEVER be re-pointed at a different one (that would let
  // one app steal another app's session).
  if (requestedClientId) {
    const requestedClient = await resolveClient(requestedClientId, req);
    if (requestedClient?.audience && !tokenClient?.audience) {
      const internalClientId = await getOrCreateInternalClientId();
      if (stored.clientId === internalClientId) {
        audience = requestedClient.audience;
        effectiveClientDbId = requestedClient.id;
        await writeAuditLog({
          userId: user.id,
          clientId: requestedClient.id,
          action: "TOKEN_REFRESHED",
          metadata: {
            sessionClientMigrated: true,
            from: "internal-default",
            to: requestedClientId,
          },
          req,
        });
      }
    }
  }

  // Rotate: create new, mark old as rotated
  const newRefresh = signRefreshToken(user.id, audience);
  const newHash = hashToken(newRefresh);
  const familyId = stored.familyId; // keep family consistent

  // Create new refresh token
  const newClientToken = await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId: effectiveClientDbId,
      tokenHash: newHash,
      scopes: stored.scopes,
      expiresAt: buildTokenExpiry(config.REFRESH_TOKEN_TTL),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers["user-agent"],
      familyId,
      deviceId: stored.deviceId,
      deviceInfo: stored.deviceInfo as any,
    },
  });

  // Mark old token as rotated and link to new one
  await prisma.refreshToken.update({
    where: { id: stored.id },
    data: {
      revokedAt: new Date(),
      revocationReason: "ROTATED",
      replacedByTokenId: newClientToken.id,
    },
  });

  const roles = await getUserRoles(user.id);
  const servicePerms = await getServiceAdminPermissions(user.id);
  const adminAudiences = adminAudiencesForPermissions(servicePerms);
  const accessAudience =
    adminAudiences.length > 0
      ? Array.from(
          new Set([
            audience ?? config.ACCESS_TOKEN_AUDIENCE,
            ...adminAudiences,
          ]),
        )
      : audience;
  const newAccess = signAccessToken(
    {
      sub: user.id,
      email: user.email,
      username: user.username,
      roles,
      sid: familyId ?? undefined,
      ...(servicePerms.length > 0 ? { perms: servicePerms } : {}),
    },
    accessAudience,
  );

  await writeAuditLog({ userId: user.id, action: "TOKEN_REFRESHED", req });

  return {
    accessToken: newAccess,
    refreshToken: newRefresh,
    expiresIn: parseTtlToSeconds(config.ACCESS_TOKEN_TTL),
    user: safeUser(user, roles),
  };
}

// ─── Logout ──────────────────────────────────────────────────────────────────

export async function logoutUser(
  userId: string,
  rawRefreshToken: string | undefined,
  req: Request,
) {
  let familyIdRevoked = false;

  if (rawRefreshToken) {
    const tokenHash = hashToken(rawRefreshToken);
    const stored = await prisma.refreshToken.findUnique({
      where: { tokenHash },
    });
    if (stored && stored.familyId) {
      await revokeSessionFamily(userId, stored.familyId, "LOGOUT");
      familyIdRevoked = true;
    } else {
      await prisma.refreshToken.updateMany({
        where: { tokenHash, userId, revokedAt: null },
        data: { revokedAt: new Date(), revocationReason: "LOGOUT" },
      });
    }
  }

  // Revoke all active sessions for this user matching this IP if they weren't already revoked by familyId
  if (!familyIdRevoked) {
    await prisma.loginSession.updateMany({
      where: {
        userId,
        revokedAt: null,
        ipAddress: req.ip ?? req.socket.remoteAddress,
      },
      data: { revokedAt: new Date(), revocationReason: "LOGOUT" },
    });
  }

  await writeAuditLog({ userId, action: "LOGOUT", req });
}

// ─── Me ──────────────────────────────────────────────────────────────────────

export async function getCurrentUser(userId: string): Promise<SafeUser> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      phone: true,
      username: true,
      displayName: true,
      firstName: true,
      lastName: true,
      dateOfBirth: true,
      avatarUrl: true,
      status: true,
      emailVerifiedAt: true,
      phoneVerifiedAt: true,
      notificationPreferences: true,
      createdAt: true,
      updatedAt: true,
      lastLoginAt: true,
      lastPasswordChangedAt: true,
    },
  });
  if (!user) throw new AppError("User not found.", "NOT_FOUND", 404);
  const roles = await getUserRoles(userId);
  return safeUser(user, roles);
}

function normalizeIdentifier(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeEmail(value: string | null | undefined): string | null {
  const normalized = normalizeIdentifier(value);
  return normalized ? normalized.toLowerCase() : null;
}

function normalizePhone(value: string | null | undefined): string | null {
  return normalizeIdentifier(value);
}

async function revokeSessionsByIds(
  userId: string,
  sessionIds: string[],
  reason: string,
) {
  if (sessionIds.length === 0) {
    return { revokedSessions: 0, revokedRefreshTokens: 0 };
  }

  const now = new Date();
  const [sessionResult, refreshTokenResult] = await prisma.$transaction([
    prisma.loginSession.updateMany({
      where: { userId, id: { in: sessionIds }, revokedAt: null },
      data: { revokedAt: now, revocationReason: reason },
    }),
    prisma.refreshToken.updateMany({
      where: { userId, familyId: { in: sessionIds }, revokedAt: null },
      data: { revokedAt: now, revocationReason: reason },
    }),
  ]);

  return {
    revokedSessions: sessionResult.count,
    revokedRefreshTokens: refreshTokenResult.count,
  };
}

async function revokeAllSessions(
  userId: string,
  reason: string,
  excludeSessionId?: string | null,
) {
  const sessions = await prisma.loginSession.findMany({
    where: {
      userId,
      revokedAt: null,
      ...(excludeSessionId ? { id: { not: excludeSessionId } } : {}),
    },
    select: { id: true },
  });

  return revokeSessionsByIds(
    userId,
    sessions.map((session) => session.id),
    reason,
  );
}

async function verifyCurrentPassword(
  userId: string,
  currentPassword: string | undefined | null,
  options?: { allowMissingPasswordOnAccount?: boolean },
) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, passwordHash: true },
  });

  if (!user) {
    throw new AppError("User not found.", "NOT_FOUND", 404);
  }

  if (!user.passwordHash) {
    if (options?.allowMissingPasswordOnAccount) {
      return user;
    }
    throw new AppError(
      'No password set on this account. Use "Forgot Password" to set one.',
      "PASSWORD_NOT_SET",
      400,
    );
  }

  if (!currentPassword) {
    throw new AppError(
      "Current password is required.",
      "CURRENT_PASSWORD_REQUIRED",
      400,
    );
  }

  const isValid = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!isValid) {
    throw new AppError(
      "Current password is incorrect.",
      "CURRENT_PASSWORD_INCORRECT",
      403,
    );
  }

  return user;
}

export async function updateCurrentUserProfile(
  userId: string,
  input: {
    displayName?: string | null;
    firstName?: string | null;
    lastName?: string | null;
    dateOfBirth?: string | null;
    username?: string | null;
    // email/phone are accepted here ONLY for the first-time-set case (an
    // account with no email/phone on file yet, e.g. completing a social
    // signup's required profile fields). Changing an ALREADY-SET email or
    // phone must go through requestEmailVerification/confirmEmailVerification
    // or requestPhoneChange/confirmPhoneChange below — see the
    // EMAIL_CHANGE_REQUIRES_VERIFICATION / PHONE_CHANGE_REQUIRES_VERIFICATION
    // guard. This endpoint must never silently replace a verified identifier.
    email?: string | null;
    phone?: string | null;
    notificationPreferences?: Partial<SafeUser["notificationPreferences"]>;
  },
  req: Request,
): Promise<SafeUser> {
  const existing = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      phone: true,
      username: true,
      notificationPreferences: true,
    },
  });

  if (!existing) {
    throw new AppError("User not found.", "NOT_FOUND", 404);
  }

  // First-time-set only: reject any attempt to change an email/phone that is
  // already on file. This is the fix for the bug where PATCH /auth/me could
  // silently overwrite a verified email/phone with no verification step.
  if (
    input.email !== undefined &&
    existing.email !== null &&
    normalizeEmail(input.email) !== existing.email
  ) {
    throw new AppError(
      "Changing your email requires verification. Use /auth/verify-email/request and /auth/verify-email/confirm.",
      "EMAIL_CHANGE_REQUIRES_VERIFICATION",
      400,
    );
  }
  if (
    input.phone !== undefined &&
    existing.phone !== null &&
    normalizePhone(input.phone) !== existing.phone
  ) {
    throw new AppError(
      "Changing your phone requires verification. Use /auth/phone-change/request and /auth/phone-change/confirm.",
      "PHONE_CHANGE_REQUIRES_VERIFICATION",
      400,
    );
  }

  const nextEmail =
    input.email === undefined ? existing.email : normalizeEmail(input.email);
  const nextPhone =
    input.phone === undefined ? existing.phone : normalizePhone(input.phone);
  const nextUsername =
    input.username === undefined
      ? existing.username
      : normalizeIdentifier(input.username);

  if (!nextEmail && !nextPhone && !nextUsername) {
    throw new AppError(
      "At least one of email, phone, or username must remain on the account.",
      "IDENTIFIER_REQUIRED",
      400,
    );
  }

  // Only reachable for a genuine first-time set (see guard above), but the
  // uniqueness check still applies so two accounts can't race onto the same
  // unverified email/phone.
  if (nextEmail && nextEmail !== existing.email) {
    const emailConflict = await prisma.user.findFirst({
      where: { email: nextEmail, id: { not: userId } },
      select: { id: true },
    });
    if (emailConflict) {
      throw new AppError(
        "That email address is already in use.",
        "EMAIL_IN_USE",
        409,
      );
    }
  }

  if (nextPhone && nextPhone !== existing.phone) {
    const phoneConflict = await prisma.user.findFirst({
      where: { phone: nextPhone, id: { not: userId } },
      select: { id: true },
    });
    if (phoneConflict) {
      throw new AppError(
        "That phone number is already in use.",
        "PHONE_IN_USE",
        409,
      );
    }
  }

  if (nextUsername && nextUsername !== existing.username) {
    const usernameConflict = await prisma.user.findFirst({
      where: { username: nextUsername, id: { not: userId } },
      select: { id: true },
    });
    if (usernameConflict) {
      throw new AppError(
        "That username is already in use.",
        "USERNAME_IN_USE",
        409,
      );
    }
  }

  const data: Record<string, unknown> = {};

  if (input.displayName !== undefined) {
    data["displayName"] = normalizeIdentifier(input.displayName);
  }
  if (input.firstName !== undefined) {
    data["firstName"] =
      input.firstName === null
        ? null
        : String(input.firstName).trim().slice(0, 64) || null;
  }
  if (input.lastName !== undefined) {
    data["lastName"] =
      input.lastName === null
        ? null
        : String(input.lastName).trim().slice(0, 64) || null;
  }
  if (input.dateOfBirth !== undefined) {
    if (input.dateOfBirth === null) {
      data["dateOfBirth"] = null;
    } else {
      const parsed = new Date(input.dateOfBirth);
      if (Number.isNaN(parsed.getTime())) {
        throw new AppError(
          "Date of birth must be a valid date.",
          "VALIDATION_ERROR",
          422,
        );
      }
      if (parsed.getTime() > Date.now()) {
        throw new AppError(
          "Date of birth cannot be in the future.",
          "VALIDATION_ERROR",
          422,
        );
      }
      data["dateOfBirth"] = parsed;
    }
  }
  if (input.email !== undefined && existing.email === null) {
    data["email"] = nextEmail;
  }
  if (input.phone !== undefined && existing.phone === null) {
    data["phone"] = nextPhone;
  }
  if (input.username !== undefined) {
    data["username"] = nextUsername;
  }
  if (input.notificationPreferences !== undefined) {
    data["notificationPreferences"] = normalizeNotificationPreferences({
      ...normalizeNotificationPreferences(existing.notificationPreferences),
      ...input.notificationPreferences,
    });
  }

  await prisma.user.update({
    where: { id: userId },
    data,
  });

  await writeAuditLog({
    userId,
    action: "PROFILE_UPDATED",
    resource: "user",
    resourceId: userId,
    req,
  });

  return getCurrentUser(userId);
}

export async function updateCurrentUserAvatar(
  userId: string,
  avatarUrl: string,
  req: Request,
) {
  const existing = await prisma.user.findUnique({
    where: { id: userId },
    select: { avatarUrl: true },
  });
  if (!existing) {
    throw new AppError("User not found.", "NOT_FOUND", 404);
  }

  await prisma.user.update({
    where: { id: userId },
    data: { avatarUrl },
  });

  await removeAvatarByUrl(existing.avatarUrl);
  await writeAuditLog({
    userId,
    action: "PROFILE_AVATAR_UPDATED",
    resource: "user",
    resourceId: userId,
    req,
  });

  return getCurrentUser(userId);
}

export async function removeCurrentUserAvatar(userId: string, req: Request) {
  const existing = await prisma.user.findUnique({
    where: { id: userId },
    select: { avatarUrl: true },
  });
  if (!existing) {
    throw new AppError("User not found.", "NOT_FOUND", 404);
  }

  await prisma.user.update({
    where: { id: userId },
    data: { avatarUrl: null },
  });

  await removeAvatarByUrl(existing.avatarUrl);
  await writeAuditLog({
    userId,
    action: "PROFILE_AVATAR_REMOVED",
    resource: "user",
    resourceId: userId,
    req,
  });

  return getCurrentUser(userId);
}

export async function listMyActiveSessions(
  userId: string,
  currentSessionId?: string,
) {
  const sessions = await prisma.loginSession.findMany({
    where: {
      userId,
      revokedAt: null,
      expiresAt: { gt: new Date() },
    },
    select: {
      id: true,
      userAgent: true,
      ipAddress: true,
      country: true,
      expiresAt: true,
      lastActiveAt: true,
      createdAt: true,
      client: {
        select: {
          id: true,
          clientId: true,
          slug: true,
          name: true,
        },
      },
    },
    orderBy: [{ lastActiveAt: "desc" }, { createdAt: "desc" }],
  });

  return sessions.map((session) => ({
    id: session.id,
    isCurrent: currentSessionId === session.id,
    client: {
      id: session.client.id,
      clientId: session.client.clientId,
      slug: session.client.slug,
      name: session.client.name,
    },
    userAgent: session.userAgent,
    ipAddress: session.ipAddress,
    country: session.country,
    createdAt: session.createdAt,
    lastActiveAt: session.lastActiveAt,
    expiresAt: session.expiresAt,
  }));
}

export async function revokeMySession(
  userId: string,
  sessionId: string,
  req: Request,
) {
  const session = await prisma.loginSession.findFirst({
    where: { id: sessionId, userId },
    select: { id: true, revokedAt: true },
  });

  if (!session) {
    throw new AppError("Session not found.", "NOT_FOUND", 404);
  }
  if (session.revokedAt) {
    return { revoked: false };
  }

  await revokeSessionsByIds(userId, [sessionId], "USER_REVOKED");
  await writeAuditLog({
    userId,
    action: "TOKEN_REVOKED",
    resource: "login_session",
    resourceId: sessionId,
    req,
  });

  return { revoked: true };
}

export async function logoutAllOtherSessions(
  userId: string,
  currentSessionId: string | undefined,
  req: Request,
) {
  if (!currentSessionId) {
    throw new AppError(
      "Current session could not be determined.",
      "SESSION_CONTEXT_MISSING",
      400,
    );
  }

  const result = await revokeAllSessions(
    userId,
    "USER_LOGOUT_ALL_OTHERS",
    currentSessionId,
  );

  await writeAuditLog({
    userId,
    action: "TOKEN_REVOKED",
    resource: "login_session",
    resourceId: currentSessionId,
    req,
    metadata: { revokedOtherSessions: result.revokedSessions },
  });

  return result;
}

export async function changeCurrentUserPassword(
  userId: string,
  currentSessionId: string | undefined,
  data: {
    currentPassword: string;
    newPassword: string;
    confirmPassword: string;
  },
  req: Request,
) {
  if (data.newPassword !== data.confirmPassword) {
    throw new AppError("Passwords do not match.", "PASSWORD_MISMATCH", 400);
  }
  if (data.currentPassword === data.newPassword) {
    throw new AppError(
      "New password must be different from the current password.",
      "PASSWORD_UNCHANGED",
      400,
    );
  }

  await verifyCurrentPassword(userId, data.currentPassword);
  const passwordHash = await bcrypt.hash(data.newPassword, BCRYPT_ROUNDS);

  await prisma.user.update({
    where: { id: userId },
    data: {
      passwordHash,
      lastPasswordChangedAt: new Date(),
    },
  });

  await revokeAllSessions(userId, "PASSWORD_CHANGED", currentSessionId ?? null);
  await writeAuditLog({
    userId,
    action: "PASSWORD_CHANGED",
    resource: "user",
    resourceId: userId,
    req,
  });

  return { success: true };
}

export async function deactivateCurrentUser(
  userId: string,
  currentSessionId: string | undefined,
  password: string | undefined,
  req: Request,
) {
  await verifyCurrentPassword(userId, password, {
    allowMissingPasswordOnAccount: true,
  });

  await prisma.user.update({
    where: { id: userId },
    data: { status: UserStatus.SUSPENDED },
  });

  await revokeAllSessions(userId, "ACCOUNT_DEACTIVATED");
  await writeAuditLog({
    userId,
    action: "ACCOUNT_SUSPENDED",
    resource: "user",
    resourceId: userId,
    req,
    metadata: { currentSessionId: currentSessionId ?? null },
  });

  return { success: true };
}

export async function deleteCurrentUser(
  userId: string,
  password: string | undefined,
  req: Request,
) {
  const existing = await prisma.user.findUnique({
    where: { id: userId },
    select: { avatarUrl: true },
  });

  if (!existing) {
    throw new AppError("User not found.", "NOT_FOUND", 404);
  }

  await verifyCurrentPassword(userId, password, {
    allowMissingPasswordOnAccount: true,
  });

  await prisma.user.update({
    where: { id: userId },
    data: {
      status: UserStatus.DELETED,
      avatarUrl: null,
    },
  });

  await revokeAllSessions(userId, "ACCOUNT_DELETED");
  await removeAvatarByUrl(existing.avatarUrl);
  await writeAuditLog({
    userId,
    action: "ACCOUNT_DELETED",
    resource: "user",
    resourceId: userId,
    req,
  });

  return { success: true };
}

// ─── Forgot Password ─────────────────────────────────────────────────────────

export async function forgotPassword(
  email: string,
  req: Request,
  clientId?: string | null,
) {
  const user = await prisma.user.findUnique({ where: { email } });
  // Always return success to prevent user enumeration
  if (!user) return;

  const token = generateOpaqueToken(32);
  const tokenHash = hashToken(token);

  await prisma.passwordResetToken.create({
    data: {
      userId: user.id,
      tokenHash,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
    },
  });

  await writeAuditLog({
    userId: user.id,
    action: "PASSWORD_RESET",
    metadata: { step: "request" },
    req,
  });

  await createAdminNotification({
    userId: user.id,
    type: "PASSWORD_RESET_REQUESTED",
    title: "Password reset requested",
    message: "A password reset request was created for your account.",
    severity: "CRITICAL",
    category: "SECURITY",
    actionUrl: "/account",
  });

  // Per-client routing (final hardening pass): mobile app clients
  // (furtail-mobile / bpa-mobile) get a deep link into their own app when
  // configured via PASSWORD_RESET_URL_BY_CLIENT; the admin panel keeps its
  // ADMIN_PANEL_ORIGIN default. See buildPasswordResetLink().
  const resetLink = buildPasswordResetLink(token, clientId);
  const resetEmailResult = await sendTemplatedEmailWithFallback(
    {
      templateKey: "password_reset",
      purpose: "PASSWORD_RESET",
      // Phase 2 incidental fix (docs/phase-2-core-identity-admin-modules.md):
      // this was `resetPasswordLink`, but the actual template/renderer
      // variable name is `resetLink` (see emailRenderer.examples.ts) — the
      // mismatch caused renderEmailTemplate() to throw "Missing required
      // variable: resetLink" on every real password-reset request, silently
      // falling back to the plain-text fallback email. Found while manually
      // verifying the OTP/communication rate limiter didn't break the
      // password-reset flow.
      variables: {
        resetLink,
        expiresIn: "1 hour",
      },
      to: email,
      userId: user.id,
      req,
    },
    "Password Reset Request",
    `You requested a password reset. Click here to reset: ${resetLink}`,
  );
  if (resetEmailResult.success) {
    incrementMetric("otp_send_total");
  }

  // Never return raw token in production
  if (process.env.NODE_ENV === "development") {
    return token;
  }
}

// ─── Reset Password ──────────────────────────────────────────────────────────

export async function resetPassword(
  token: string,
  newPassword: string,
  req: Request,
) {
  const tokenHash = hashToken(token);
  const record = await prisma.passwordResetToken.findUnique({
    where: { tokenHash },
  });

  if (!record || record.usedAt || record.expiresAt < new Date()) {
    throw new AppError(
      "Reset token is invalid or has expired.",
      "TOKEN_INVALID",
      400,
    );
  }

  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  const user = await prisma.user.findUnique({ where: { id: record.userId } });

  await prisma.$transaction([
    prisma.user.update({
      where: { id: record.userId },
      data: { passwordHash },
    }),
    prisma.passwordResetToken.update({
      where: { tokenHash },
      data: { usedAt: new Date() },
    }),
    // Revoke all existing refresh tokens for security
    prisma.refreshToken.updateMany({
      where: { userId: record.userId, revokedAt: null },
      data: { revokedAt: new Date() },
    }),
  ]);

  await writeAuditLog({
    userId: record.userId,
    action: "PASSWORD_CHANGE",
    req,
  });

  // Send password changed notification email
  if (user?.email) {
    try {
      await sendTemplatedEmailWithFallback(
        {
          templateKey: "password_changed",
          variables: {
            userName: user.displayName || user.email,
          },
          to: user.email,
          userId: user.id,
        },
        "Your password has been changed",
        "Your account password was successfully reset and all existing sessions have been revoked for security.",
      );
    } catch (e) {
      console.error("Failed to send password changed notification email", e);
    }
  }

  await createAdminNotification({
    userId: record.userId,
    type: "PASSWORD_RESET_COMPLETED",
    title: "Password reset completed",
    message:
      "Your account password was reset and existing sessions were revoked.",
    severity: "CRITICAL",
    category: "SECURITY",
    actionUrl: "/sessions",
  });
}

// ─── Email Verification ──────────────────────────────────────────────────────

export async function requestEmailVerification(
  userId: string,
  email: string,
  req: Request,
) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new AppError("User not found.", "NOT_FOUND", 404);
  const normalizedTarget = normalizeEmail(email);
  if (!normalizedTarget) {
    throw new AppError(
      "A valid email address is required.",
      "VALIDATION_ERROR",
      422,
    );
  }
  // Requesting verification for the SAME email that is already verified is a
  // no-op error. Requesting a DIFFERENT email is a change request and is
  // always allowed (even if the current email is verified) — this is the
  // only supported path for changing a verified email; see
  // confirmEmailVerification below, which applies record.email to the user
  // on confirm.
  if (user.emailVerifiedAt && user.email === normalizedTarget) {
    throw new AppError("Email is already verified.", "ALREADY_VERIFIED", 400);
  }
  const conflict = await prisma.user.findFirst({
    where: { email: normalizedTarget, id: { not: userId } },
    select: { id: true },
  });
  if (conflict) {
    throw new AppError(
      "That email address is already in use.",
      "EMAIL_IN_USE",
      409,
    );
  }

  const token = generateOpaqueToken(32);
  const tokenHash = hashToken(token);

  await prisma.emailVerificationToken.create({
    data: {
      userId,
      email: normalizedTarget,
      tokenHash,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    },
  });

  await writeAuditLog({
    userId,
    action: "EMAIL_VERIFIED",
    metadata: { step: "request" },
    req,
  });
  await logAbuseSignal({
    route: "auth-verify-email-request",
    req,
    identifier: normalizedTarget,
    userId,
    threat: "OTP_ABUSE_DETECTED",
    blockAfter: 8,
  });

  // Phase 2.5 incidental fix (docs/phase-2-5-public-auth-rs256-oidc.md):
  // same APP_URL-instead-of-frontend bug fixed above.
  const verificationLink = `${config.ADMIN_PANEL_ORIGIN}/auth/user/verify-email?token=${token}`;
  const requestUser = await prisma.user.findUnique({ where: { id: userId } });
  const verificationEmailResult = await sendTemplatedEmailWithFallback(
    {
      templateKey: "email_verification",
      purpose: "REGISTER",
      variables: {
        userName: requestUser?.displayName || normalizedTarget,
        verificationLink,
        expiresIn: "24 hours",
      },
      to: normalizedTarget,
      userId,
      req,
    },
    "Verify your email",
    `Please verify your email by clicking this link: ${verificationLink}`,
  );
  if (verificationEmailResult.success) {
    incrementMetric("otp_send_total");
  }

  if (process.env.NODE_ENV === "development") {
    return token;
  }
}

export async function confirmEmailVerification(token: string, req: Request) {
  const tokenHash = hashToken(token);
  const record = await prisma.emailVerificationToken.findUnique({
    where: { tokenHash },
  });

  if (!record || record.usedAt || record.expiresAt < new Date()) {
    await logAbuseSignal({
      route: "auth-verify-email-confirm",
      req,
      identifier: token.slice(0, 16),
      threat: "OTP_ABUSE_DETECTED",
      blockAfter: 8,
    });
    throw new AppError(
      "Verification token is invalid or has expired.",
      "TOKEN_INVALID",
      400,
    );
  }

  // Re-check uniqueness at confirm time (not just at request time) in case
  // another account claimed this email in the interim.
  const conflict = await prisma.user.findFirst({
    where: { email: record.email, id: { not: record.userId } },
    select: { id: true },
  });
  if (conflict) {
    throw new AppError(
      "That email address is already in use.",
      "EMAIL_IN_USE",
      409,
    );
  }

  // Captured BEFORE the update so we can notify the account's previous
  // email address (if any, and if it's actually changing) that this
  // change happened — a basic account-takeover tripwire. Best-effort:
  // never blocks or fails the change itself.
  const beforeUpdate = await prisma.user.findUnique({
    where: { id: record.userId },
    select: { email: true },
  });
  const previousEmail = beforeUpdate?.email ?? null;

  const user = await prisma.user.update({
    where: { id: record.userId },
    // record.email is the token's target address — applying it here (not
    // just flipping emailVerifiedAt) is what makes this endpoint work as an
    // email CHANGE flow, not only an initial-verification flow.
    data: {
      email: record.email,
      emailVerifiedAt: new Date(),
      status: UserStatus.ACTIVE,
    },
  });

  if (previousEmail && previousEmail !== record.email) {
    try {
      await sendEmail(
        previousEmail,
        "Your account email was changed",
        "The email address on your account was just changed. If this wasn't you, please contact support immediately and secure your account.",
        "<p>The email address on your account was just changed. If this wasn't you, please contact support immediately and secure your account.</p>",
      );
    } catch (e) {
      console.error("Failed to send email-change notice to previous address");
    }
  }

  await prisma.emailVerificationToken.update({
    where: { tokenHash },
    data: { usedAt: new Date() },
  });

  await writeAuditLog({
    userId: record.userId,
    action: "EMAIL_VERIFIED",
    metadata: { step: "confirm" },
    req,
  });

  // Send welcome email after email verification
  if (user.email) {
    try {
      await sendWelcomeEmail(
        user.email,
        user.displayName || user.email,
        user.id,
      );
    } catch (e) {
      console.error("Failed to send welcome email", e);
    }
  }
}

// ─── Verified phone change (mirrors requestEmailVerification/
// confirmEmailVerification above, but via a 6-digit SMS OTP instead of an
// emailed link, since phones can't receive clickable verification links) ──

const PHONE_CHANGE_CODE_TTL_MS = 15 * 60 * 1000; // 15 minutes
const PHONE_CHANGE_MAX_ATTEMPTS = 5;

function generatePhoneChangeCode(): string {
  return String(Math.floor(100000 + Math.random() * 900000));
}

export async function requestPhoneChange(
  userId: string,
  phone: string,
  req: Request,
) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new AppError("User not found.", "NOT_FOUND", 404);
  const normalizedTarget = normalizePhone(phone);
  if (!normalizedTarget) {
    throw new AppError(
      "A valid phone number is required.",
      "VALIDATION_ERROR",
      422,
    );
  }
  if (user.phoneVerifiedAt && user.phone === normalizedTarget) {
    throw new AppError("Phone is already verified.", "ALREADY_VERIFIED", 400);
  }
  const conflict = await prisma.user.findFirst({
    where: { phone: normalizedTarget, id: { not: userId } },
    select: { id: true },
  });
  if (conflict) {
    throw new AppError(
      "That phone number is already in use.",
      "PHONE_IN_USE",
      409,
    );
  }

  const code = generatePhoneChangeCode();
  const codeHash = hashToken(code);

  await prisma.phoneChangeToken.create({
    data: {
      userId,
      phone: normalizedTarget,
      codeHash,
      expiresAt: new Date(Date.now() + PHONE_CHANGE_CODE_TTL_MS),
    },
  });

  await writeAuditLog({
    userId,
    action: "PHONE_VERIFIED",
    metadata: { step: "change_request" },
    req,
  });
  await logAbuseSignal({
    route: "auth-phone-change-request",
    req,
    identifier: normalizedTarget,
    userId,
    threat: "OTP_ABUSE_DETECTED",
    blockAfter: 8,
  });

  try {
    await sendOtpSms({
      phone: normalizedTarget,
      otp: code,
      purpose: "GENERAL",
      minutes: PHONE_CHANGE_CODE_TTL_MS / 60000,
      userId,
    });
  } catch (e) {
    console.error("Failed to send phone-change SMS", e);
  }

  // Never returned/logged outside development — the code itself must never
  // reach logs, audit trails, or API responses in a real environment.
  if (process.env.NODE_ENV === "development") {
    return code;
  }
}

export async function confirmPhoneChange(
  userId: string,
  code: string,
  req: Request,
) {
  const record = await prisma.phoneChangeToken.findFirst({
    where: { userId, usedAt: null },
    orderBy: { createdAt: "desc" },
  });

  if (!record || record.expiresAt < new Date()) {
    throw new AppError(
      "Verification code is invalid or has expired.",
      "TOKEN_INVALID",
      400,
    );
  }
  if (record.attempts >= PHONE_CHANGE_MAX_ATTEMPTS) {
    throw new AppError(
      "Too many attempts. Request a new code.",
      "OTP_TOO_MANY_ATTEMPTS",
      429,
    );
  }

  const codeHash = hashToken(code);
  if (codeHash !== record.codeHash) {
    await prisma.phoneChangeToken.update({
      where: { id: record.id },
      data: { attempts: { increment: 1 } },
    });
    await logAbuseSignal({
      route: "auth-phone-change-confirm",
      req,
      identifier: userId,
      userId,
      threat: "OTP_ABUSE_DETECTED",
      blockAfter: 8,
    });
    throw new AppError(
      "Verification code is invalid or has expired.",
      "TOKEN_INVALID",
      400,
    );
  }

  // Re-check uniqueness at confirm time, same reasoning as the email flow.
  const conflict = await prisma.user.findFirst({
    where: { phone: record.phone, id: { not: userId } },
    select: { id: true },
  });
  if (conflict) {
    throw new AppError(
      "That phone number is already in use.",
      "PHONE_IN_USE",
      409,
    );
  }

  // Captured BEFORE the update so we can notify the account's previous
  // phone (if any, and if it's actually changing) — same account-takeover
  // tripwire as the email-change flow above. Best-effort only.
  const beforeUpdate = await prisma.user.findUnique({
    where: { id: userId },
    select: { phone: true },
  });
  const previousPhone = beforeUpdate?.phone ?? null;

  await prisma.user.update({
    where: { id: userId },
    data: { phone: record.phone, phoneVerifiedAt: new Date() },
  });

  await prisma.phoneChangeToken.update({
    where: { id: record.id },
    data: { usedAt: new Date() },
  });

  await writeAuditLog({
    userId,
    action: "PHONE_VERIFIED",
    metadata: { step: "change_confirm" },
    req,
  });

  if (previousPhone && previousPhone !== record.phone) {
    try {
      await sendOtpSms({
        phone: previousPhone,
        // Not actually an OTP — reusing the GENERAL-purpose SMS template
        // pipeline (same one requestPhoneChange uses) since there is no
        // separate plain-notice SMS path in this codebase. `otp` here is
        // just the templated message body, never a real one-time code.
        otp: "Your account phone number was just changed. If this wasn't you, contact support immediately.",
        purpose: "GENERAL",
        userId,
      });
    } catch (e) {
      console.error("Failed to send phone-change notice to previous number");
    }
  }
}

export async function heartbeatPresence(
  userId: string,
  appId: string | null | undefined,
) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { status: true },
  });
  if (!user) throw new AppError("User not found.", "NOT_FOUND", 404);
  if (
    user.status === UserStatus.SUSPENDED ||
    user.status === UserStatus.DELETED
  ) {
    throw new AppError("Account is not active.", "ACCOUNT_INACTIVE", 403);
  }
  return recordPresenceHeartbeat({ userId, appId: appId ?? undefined });
}

// ─── Internal helpers ────────────────────────────────────────────────────────

let _internalClientId: string | null = null;
export async function getOrCreateInternalClientId(): Promise<string> {
  if (_internalClientId) return _internalClientId;
  const client = await prisma.authClient.findFirst({
    where: { slug: "world-pet-association" },
  });
  if (!client) {
    throw new Error(
      'Internal client "world-pet-association" not found in DB. Did you run the seed?',
    );
  }
  _internalClientId = client.id;
  return _internalClientId;
}
