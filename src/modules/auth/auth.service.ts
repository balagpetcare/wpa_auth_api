import bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { UserStatus } from '@prisma/client';
import { prisma } from '../../lib/db.js';
import { config } from '../../config/index.js';
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  hashToken,
  generateOpaqueToken,
  parseTtlToSeconds,
} from '../../lib/tokens.js';
import { AppError } from '../../lib/errors.js';
import { writeAuditLog, writeSecurityEvent } from '../../lib/audit.js';
import { createAdminNotification } from '../../lib/adminNotifications.js';
import { sendEmail } from '../../lib/mailer.js';
import { sendTemplatedEmail, sendTemplatedEmailWithFallback } from '../../lib/sendTemplatedEmail.js';
import { sendLoginAlertEmail, sendWelcomeEmail } from '../../lib/emailNotifications.js';
import { Request } from 'express';
import { logAbuseSignal, clearRisk, clearLoginAbuseState } from '../../lib/antiAbuse.js';
import { recordPresenceHeartbeat } from '../../lib/presence.js';
import { incrementMetric } from '../../lib/metrics.js';

const BCRYPT_ROUNDS = 12;

export type SafeUser = {
  id: string;
  email: string | null;
  phone: string | null;
  username: string | null;
  displayName: string | null;
  avatarUrl: string | null;
  status: UserStatus;
  emailVerifiedAt: Date | null;
  phoneVerifiedAt: Date | null;
  roles: string[];
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
};

function safeUser(user: any, roles: string[] = []): SafeUser {
  return {
    id: user.id,
    email: user.email,
    phone: user.phone,
    username: user.username,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    status: user.status,
    emailVerifiedAt: user.emailVerifiedAt,
    phoneVerifiedAt: user.phoneVerifiedAt,
    roles,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    lastLoginAt: user.lastLoginAt,
  };
}

async function getUserRoles(userId: string): Promise<string[]> {
  const userRoles = await prisma.userRole.findMany({
    where: { userId },
    include: { role: true },
  });
  return userRoles.map((ur) => ur.role.name);
}

async function resolveClient(clientId?: string, req?: Request) {
  if (!clientId) return null;
  const client = await prisma.authClient.findUnique({ where: { clientId } });
  if (!client || client.status !== 'ACTIVE') return null;

  if (req && req.headers.origin) {
    const origin = req.headers.origin;
    if (!client.allowedOrigins.includes(origin) && !client.allowedOrigins.includes('*')) {
      console.warn(`[SECURITY] Blocked invalid origin "${origin}" for client "${client.id}" in auth flow`);
      await writeSecurityEvent({
        type: 'SUSPICIOUS_OAUTH',
        severity: 'MEDIUM',
        metadata: { reason: 'invalid_origin', origin, clientId: client.id },
        req,
      });
      throw new AppError('Origin not allowed for this client.', 'INVALID_ORIGIN', 403);
    }
  }

  return client;
}

function buildTokenExpiry(ttl: string): Date {
  return new Date(Date.now() + parseTtlToSeconds(ttl) * 1000);
}

// ─── Register ────────────────────────────────────────────────────────────────

export async function registerUser(
  opts: { email?: string; phone?: string; username?: string; password: string; displayName?: string; clientId?: string },
  req: Request,
) {
  if (!opts.email && !opts.phone && !opts.username) {
    throw new AppError('Provide at least one of email, phone, or username.', 'MISSING_IDENTIFIER');
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
  if (existing) throw new AppError('An account with those credentials already exists.', 'ALREADY_EXISTS', 409);

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
  const defaultRole = await prisma.role.findFirst({ where: { name: { in: ['user', 'USER'] } } });
  if (defaultRole) {
    await prisma.userRole.create({ data: { userId: user.id, roleId: defaultRole.id } });
  }

  if (client) {
    await prisma.userClientAccess.upsert({
      where: { userId_clientId: { userId: user.id, clientId: client.id } },
      update: {},
      create: { userId: user.id, clientId: client.id, status: 'ACTIVE' },
    });
  }

  await writeAuditLog({ userId: user.id, clientId: client?.id, action: 'REGISTER', req });

  if (opts.email) {
    try {
      const token = generateOpaqueToken(32);
      const tokenHash = hashToken(token);
      await prisma.emailVerificationToken.create({
        data: { userId: user.id, email: opts.email, tokenHash, expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) },
      });
      // Phase 2.5 incidental fix (docs/phase-2-5-public-auth-rs256-oidc.md):
      // this pointed at config.APP_URL, which is this API server's own base
      // URL (http://localhost:5010 by default) — not a frontend page, so
      // the link in every verification email 404'd. ADMIN_PANEL_ORIGIN is
      // the Next.js frontend that now hosts the real public verify-email
      // page at /auth/user/verify-email.
      const verificationLink = `${config.ADMIN_PANEL_ORIGIN}/auth/user/verify-email?token=${token}`;
      await sendTemplatedEmailWithFallback(
        {
          templateKey: 'email_verification',
          purpose: 'REGISTER',
          variables: {
            userName: opts.displayName || opts.email,
            verificationLink,
            expiresIn: '24 hours',
          },
          to: opts.email,
          userId: user.id,
          clientId: client?.id || null,
          req,
        },
        'Welcome! Please verify your email',
        `Please verify your email by clicking this link: ${verificationLink}`
      );
    } catch (e) {
      console.error('Failed to send registration verification email', e);
    }
  }

  return safeUser(user, defaultRole ? ['user'] : []);
}

// ─── Login ───────────────────────────────────────────────────────────────────

export async function loginUser(
  opts: { emailOrUsername: string; password: string; clientId?: string },
  req: Request,
) {
  const identifier = opts.emailOrUsername.trim().toLowerCase();
  const loginAbuseIdentifier = `${identifier}:${req.ip ?? req.socket.remoteAddress ?? 'unknown'}`;
  const isEmail = identifier.includes('@');

  const user = await prisma.user.findFirst({
    where: isEmail
      ? { email: identifier }
      : { OR: [{ username: identifier }, { email: identifier }, { phone: identifier }] },
  });

  if (!user || !user.passwordHash) {
    incrementMetric('login_failure_total');
    await logAbuseSignal({ route: 'auth-login', req, identifier: loginAbuseIdentifier, threat: 'BOT_TRAFFIC_SPIKE', blockAfter: 6, blockTtlMs: 30 * 60 * 1000 });
    throw new AppError('Invalid credentials.', 'INVALID_CREDENTIALS', 401);
  }

  const valid = await bcrypt.compare(opts.password, user.passwordHash);
  if (!valid) {
    incrementMetric('login_failure_total');
    await writeAuditLog({ userId: user.id, action: 'LOGIN', metadata: { success: false }, req });

    // Check failed login attempts threshold (Requirement 2 & 11)
    try {
      const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
      const recentLoginAudits = await prisma.auditLog.findMany({
        where: {
          userId: user.id,
          action: 'LOGIN',
          createdAt: { gte: fifteenMinutesAgo },
        },
        take: 6,
        orderBy: { createdAt: 'desc' },
      });
      const failedCount = recentLoginAudits.filter(log => {
        const meta = log.metadata as any;
        return meta && meta.success === false;
      }).length;

      if (failedCount >= 5) {
        await createAdminNotification({
          userId: user.id,
          type: 'MULTIPLE_FAILED_LOGINS',
          title: 'Multiple failed login attempts',
          message: `Multiple failed login attempts (${failedCount}) were detected for your account.`,
          severity: 'CRITICAL',
          category: 'SECURITY',
          actionUrl: '/security-events',
        });
      }
    } catch (err) {
      console.error('Failed to process failed login threshold:', err);
    }

    await logAbuseSignal({ route: 'auth-login', req, identifier: loginAbuseIdentifier, userId: user.id, threat: 'BOT_TRAFFIC_SPIKE', blockAfter: 6, blockTtlMs: 30 * 60 * 1000 });
    throw new AppError('Invalid credentials.', 'INVALID_CREDENTIALS', 401);
  }

  if (user.status === UserStatus.SUSPENDED) {
    throw new AppError('Your account has been suspended.', 'ACCOUNT_SUSPENDED', 403);
  }
  if (user.status === UserStatus.DELETED) {
    throw new AppError('Invalid credentials.', 'INVALID_CREDENTIALS', 401);
  }

  const client = await resolveClient(opts.clientId, req);
  if (client) {
    await prisma.userClientAccess.upsert({
      where: { userId_clientId: { userId: user.id, clientId: client.id } },
      update: {},
      create: { userId: user.id, clientId: client.id, status: 'ACTIVE' },
    });
  }

  const roles = await getUserRoles(user.id);
  const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username, roles });
  const refreshToken = signRefreshToken(user.id);
  const tokenHash = hashToken(refreshToken);

  const session = await prisma.loginSession.create({
    data: {
      userId: user.id,
      clientId: client?.id ?? (await getOrCreateInternalClientId()),
      sessionToken: generateOpaqueToken(),
      expiresAt: buildTokenExpiry(config.REFRESH_TOKEN_TTL),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
    },
  });

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId: client?.id ?? (await getOrCreateInternalClientId()),
      tokenHash,
      scopes: ['openid', 'offline_access'],
      expiresAt: buildTokenExpiry(config.REFRESH_TOKEN_TTL),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
      familyId: session.id,
    },
  });

  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() },
  });

  await writeAuditLog({ userId: user.id, clientId: client?.id, action: 'LOGIN', metadata: { success: true }, req });
  incrementMetric('login_success_total');
  await clearRisk({ req, identifier });
  await clearLoginAbuseState({ req, identifier: loginAbuseIdentifier });

  // Sensitive/security login checks (Requirement 2 & 11)
  try {
    const previousSession = await prisma.loginSession.findFirst({
      where: {
        userId: user.id,
        NOT: { id: session.id },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (previousSession) {
      if (session.ipAddress && previousSession.ipAddress && session.ipAddress !== previousSession.ipAddress) {
        await createAdminNotification({
          userId: user.id,
          type: 'NEW_IP_LOGIN',
          title: 'New IP login detected',
          message: `A login was recorded from a new IP address: ${session.ipAddress}.`,
          severity: 'WARNING',
          category: 'SECURITY',
          actionUrl: '/sessions',
        });
      }

      if (session.userAgent && previousSession.userAgent && session.userAgent !== previousSession.userAgent) {
        await createAdminNotification({
          userId: user.id,
          type: 'NEW_DEVICE_LOGIN',
          title: 'New device login detected',
          message: `A login was recorded from a new device or browser.`,
          severity: 'WARNING',
          category: 'SECURITY',
          actionUrl: '/sessions',
        });
      }

      if (session.country && previousSession.country && session.country !== previousSession.country) {
        await createAdminNotification({
          userId: user.id,
          type: 'UNUSUAL_LOCATION_LOGIN',
          title: 'Unusual location login detected',
          message: `A login was recorded from a different country: ${session.country}.`,
          severity: 'CRITICAL',
          category: 'SECURITY',
          actionUrl: '/sessions',
        });
      }
    }
  } catch (err) {
    console.error('Failed to process sensitive login checks:', err);
  }

  // Send login alert email
  if (user.email) {
    try {
      await sendLoginAlertEmail(
        user.email,
        user.displayName || user.email,
        req.ip ?? req.socket.remoteAddress?.toString() ?? null,
        req.headers['user-agent']?.toString() ?? null,
        user.id,
        client?.id || null,
      );
    } catch (e) {
      console.error('Failed to send login alert email', e);
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

export async function revokeSessionFamily(userId: string, familyId: string, reason: string) {
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

export async function refreshTokens(rawRefreshToken: string, req: Request) {
  let payload: { sub: string };
  try {
    payload = verifyRefreshToken(rawRefreshToken);
  } catch {
    throw new AppError('Invalid or expired refresh token.', 'TOKEN_INVALID', 401);
  }

  const tokenHash = hashToken(rawRefreshToken);
  const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });

  if (!stored) {
    throw new AppError('Refresh token is invalid or has been revoked.', 'TOKEN_REVOKED', 401);
  }

  // Reuse detection:
  if (stored.revokedAt || stored.expiresAt < new Date()) {
    if (stored.revokedAt && stored.revocationReason === 'ROTATED') {
      // Reused a rotated token!
      if (!stored.reusedAt) {
        // Mark as reused to prevent duplicate processing
        await prisma.refreshToken.update({
          where: { id: stored.id },
          data: { reusedAt: new Date() },
        });

        // Revoke the session family
        if (stored.familyId) {
          await revokeSessionFamily(stored.userId, stored.familyId, 'REUSE_DETECTED');
        }

        // Increase abuse risk score for IP
        await logAbuseSignal({
          route: 'auth-refresh',
          req,
          identifier: rawRefreshToken.slice(0, 16),
          threat: 'REFRESH_TOKEN_REUSE_DETECTED',
          blockAfter: 3,
        });
        incrementMetric('refresh_token_reuse_total');

        // Write SecurityEvent
        await writeSecurityEvent({
          type: 'TOKEN_REUSE_DETECTED',
          severity: 'HIGH',
          metadata: {
            userId: stored.userId,
            clientId: stored.clientId,
            familyId: stored.familyId,
            ipAddress: req.ip ?? req.socket.remoteAddress,
            userAgent: req.headers['user-agent'],
          },
          req,
        });

        // Create AdminNotification/security notification
        await createAdminNotification({
          userId: stored.userId,
          type: 'REFRESH_TOKEN_REUSE_DETECTED',
          title: 'Potential refresh token theft detected',
          message: `Refresh token reuse detected for user ${stored.userId}. Entire session family has been revoked.`,
          severity: 'CRITICAL',
          category: 'SECURITY',
          metadata: {
            userId: stored.userId,
            clientId: stored.clientId,
            familyId: stored.familyId,
          },
        });
      }

      throw new AppError('Refresh token reuse detected.', 'TOKEN_REVOKED', 401);
    }

    // Normal invalid/revoked/expired token
    await logAbuseSignal({ route: 'auth-refresh', req, identifier: rawRefreshToken.slice(0, 16), threat: 'SUSPICIOUS_ACTIVITY_BLOCKED', blockAfter: 8 });
    throw new AppError('Refresh token is invalid or has been revoked.', 'TOKEN_REVOKED', 401);
  }

  if (stored.userId !== payload.sub) {
    throw new AppError('Token mismatch.', 'TOKEN_INVALID', 401);
  }

  const user = await prisma.user.findUnique({ where: { id: payload.sub } });
  if (!user || user.status === UserStatus.DELETED || user.status === UserStatus.SUSPENDED) {
    throw new AppError('User is not active.', 'ACCOUNT_INACTIVE', 403);
  }

  // Verify that the login session is not revoked
  if (stored.familyId) {
    const session = await prisma.loginSession.findUnique({ where: { id: stored.familyId } });
    if (!session || session.revokedAt) {
      // The session family is already revoked, so we should revoke this token too
      await prisma.refreshToken.update({
        where: { id: stored.id },
        data: { revokedAt: new Date(), revocationReason: 'SESSION_REVOKED' },
      });
      throw new AppError('Session is invalid or has been revoked.', 'TOKEN_REVOKED', 401);
    }
  }

  // Rotate: create new, mark old as rotated
  const newRefresh = signRefreshToken(user.id);
  const newHash = hashToken(newRefresh);
  const familyId = stored.familyId; // keep family consistent

  // Create new refresh token
  const newClientToken = await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId: stored.clientId,
      tokenHash: newHash,
      scopes: stored.scopes,
      expiresAt: buildTokenExpiry(config.REFRESH_TOKEN_TTL),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
      familyId,
    },
  });

  // Mark old token as rotated and link to new one
  await prisma.refreshToken.update({
    where: { id: stored.id },
    data: {
      revokedAt: new Date(),
      revocationReason: 'ROTATED',
      replacedByTokenId: newClientToken.id,
    },
  });

  const roles = await getUserRoles(user.id);
  const newAccess = signAccessToken({ sub: user.id, email: user.email, username: user.username, roles });

  await writeAuditLog({ userId: user.id, action: 'TOKEN_REFRESHED', req });

  return {
    accessToken: newAccess,
    refreshToken: newRefresh,
    expiresIn: parseTtlToSeconds(config.ACCESS_TOKEN_TTL),
    user: safeUser(user, roles),
  };
}

// ─── Logout ──────────────────────────────────────────────────────────────────

export async function logoutUser(userId: string, rawRefreshToken: string | undefined, req: Request) {
  let familyIdRevoked = false;

  if (rawRefreshToken) {
    const tokenHash = hashToken(rawRefreshToken);
    const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });
    if (stored && stored.familyId) {
      await revokeSessionFamily(userId, stored.familyId, 'LOGOUT');
      familyIdRevoked = true;
    } else {
      await prisma.refreshToken.updateMany({
        where: { tokenHash, userId, revokedAt: null },
        data: { revokedAt: new Date(), revocationReason: 'LOGOUT' },
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
      data: { revokedAt: new Date(), revocationReason: 'LOGOUT' },
    });
  }

  await writeAuditLog({ userId, action: 'LOGOUT', req });
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
      avatarUrl: true,
      status: true,
      emailVerifiedAt: true,
      phoneVerifiedAt: true,
      createdAt: true,
      updatedAt: true,
      lastLoginAt: true
    }
  });
  if (!user) throw new AppError('User not found.', 'NOT_FOUND', 404);
  const roles = await getUserRoles(userId);
  return safeUser(user, roles);
}

// ─── Forgot Password ─────────────────────────────────────────────────────────

export async function forgotPassword(email: string, req: Request) {
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

  await writeAuditLog({ userId: user.id, action: 'PASSWORD_RESET', metadata: { step: 'request' }, req });

  await createAdminNotification({
    userId: user.id,
    type: 'PASSWORD_RESET_REQUESTED',
    title: 'Password reset requested',
    message: 'A password reset request was created for your account.',
    severity: 'CRITICAL',
    category: 'SECURITY',
    actionUrl: '/account',
  });

  // Phase 2.5 incidental fix (docs/phase-2-5-public-auth-rs256-oidc.md):
  // same APP_URL-instead-of-frontend bug as the email-verification link
  // above — this pointed at the API server itself, not a real page.
  const resetLink = `${config.ADMIN_PANEL_ORIGIN}/auth/user/reset-password?token=${token}`;
  const resetEmailResult = await sendTemplatedEmailWithFallback(
    {
      templateKey: 'password_reset',
      purpose: 'PASSWORD_RESET',
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
        expiresIn: '1 hour',
      },
      to: email,
      userId: user.id,
      req,
    },
    'Password Reset Request',
    `You requested a password reset. Click here to reset: ${resetLink}`
  );
  if (resetEmailResult.success) {
    incrementMetric('otp_send_total');
  }

  // Never return raw token in production
  if (process.env.NODE_ENV === 'development') {
    return token;
  }
}

// ─── Reset Password ──────────────────────────────────────────────────────────

export async function resetPassword(token: string, newPassword: string, req: Request) {
  const tokenHash = hashToken(token);
  const record = await prisma.passwordResetToken.findUnique({ where: { tokenHash } });

  if (!record || record.usedAt || record.expiresAt < new Date()) {
    throw new AppError('Reset token is invalid or has expired.', 'TOKEN_INVALID', 400);
  }

  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  const user = await prisma.user.findUnique({ where: { id: record.userId } });

  await prisma.$transaction([
    prisma.user.update({ where: { id: record.userId }, data: { passwordHash } }),
    prisma.passwordResetToken.update({ where: { tokenHash }, data: { usedAt: new Date() } }),
    // Revoke all existing refresh tokens for security
    prisma.refreshToken.updateMany({ where: { userId: record.userId, revokedAt: null }, data: { revokedAt: new Date() } }),
  ]);

  await writeAuditLog({ userId: record.userId, action: 'PASSWORD_CHANGE', req });

  // Send password changed notification email
  if (user?.email) {
    try {
      await sendTemplatedEmailWithFallback(
        {
          templateKey: 'password_changed',
          variables: {
            userName: user.displayName || user.email,
          },
          to: user.email,
          userId: user.id,
        },
        'Your password has been changed',
        'Your account password was successfully reset and all existing sessions have been revoked for security.'
      );
    } catch (e) {
      console.error('Failed to send password changed notification email', e);
    }
  }

  await createAdminNotification({
    userId: record.userId,
    type: 'PASSWORD_RESET_COMPLETED',
    title: 'Password reset completed',
    message: 'Your account password was reset and existing sessions were revoked.',
    severity: 'CRITICAL',
    category: 'SECURITY',
    actionUrl: '/sessions',
  });
}

// ─── Email Verification ──────────────────────────────────────────────────────

export async function requestEmailVerification(userId: string, email: string, req: Request) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new AppError('User not found.', 'NOT_FOUND', 404);
  if (user.emailVerifiedAt) throw new AppError('Email is already verified.', 'ALREADY_VERIFIED', 400);

  const token = generateOpaqueToken(32);
  const tokenHash = hashToken(token);

  await prisma.emailVerificationToken.create({
    data: {
      userId,
      email,
      tokenHash,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    },
  });

  await writeAuditLog({ userId, action: 'EMAIL_VERIFIED', metadata: { step: 'request' }, req });
  await logAbuseSignal({ route: 'auth-verify-email-request', req, identifier: email, userId, threat: 'OTP_ABUSE_DETECTED', blockAfter: 8 });

  // Phase 2.5 incidental fix (docs/phase-2-5-public-auth-rs256-oidc.md):
  // same APP_URL-instead-of-frontend bug fixed above.
  const verificationLink = `${config.ADMIN_PANEL_ORIGIN}/auth/user/verify-email?token=${token}`;
  const requestUser = await prisma.user.findUnique({ where: { id: userId } });
  const verificationEmailResult = await sendTemplatedEmailWithFallback(
    {
      templateKey: 'email_verification',
      purpose: 'REGISTER',
      variables: {
        userName: requestUser?.displayName || email,
        verificationLink,
        expiresIn: '24 hours',
      },
      to: email,
      userId,
      req,
    },
    'Verify your email',
    `Please verify your email by clicking this link: ${verificationLink}`
  );
  if (verificationEmailResult.success) {
    incrementMetric('otp_send_total');
  }

  if (process.env.NODE_ENV === 'development') {
    return token;
  }
}

export async function confirmEmailVerification(token: string, req: Request) {
  const tokenHash = hashToken(token);
  const record = await prisma.emailVerificationToken.findUnique({ where: { tokenHash } });

  if (!record || record.usedAt || record.expiresAt < new Date()) {
    await logAbuseSignal({ route: 'auth-verify-email-confirm', req, identifier: token.slice(0, 16), threat: 'OTP_ABUSE_DETECTED', blockAfter: 8 });
    throw new AppError('Verification token is invalid or has expired.', 'TOKEN_INVALID', 400);
  }

  const user = await prisma.user.update({
    where: { id: record.userId },
    data: { emailVerifiedAt: new Date(), status: UserStatus.ACTIVE },
  });

  await prisma.emailVerificationToken.update({ where: { tokenHash }, data: { usedAt: new Date() } });

  await writeAuditLog({ userId: record.userId, action: 'EMAIL_VERIFIED', metadata: { step: 'confirm' }, req });

  // Send welcome email after email verification
  if (user.email) {
    try {
      await sendWelcomeEmail(user.email, user.displayName || user.email, user.id);
    } catch (e) {
      console.error('Failed to send welcome email', e);
    }
  }
}

export async function heartbeatPresence(userId: string, appId: string | null | undefined) {
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { status: true } });
  if (!user) throw new AppError('User not found.', 'NOT_FOUND', 404);
  if (user.status === UserStatus.SUSPENDED || user.status === UserStatus.DELETED) {
    throw new AppError('Account is not active.', 'ACCOUNT_INACTIVE', 403);
  }
  return recordPresenceHeartbeat({ userId, appId: appId ?? undefined });
}

// ─── Internal helpers ────────────────────────────────────────────────────────

let _internalClientId: string | null = null;
async function getOrCreateInternalClientId(): Promise<string> {
  if (_internalClientId) return _internalClientId;
  const client = await prisma.authClient.findFirst({ where: { slug: 'world-pet-association' } });
  if (!client) {
    throw new Error('Internal client "world-pet-association" not found in DB. Did you run the seed?');
  }
  _internalClientId = client.id;
  return _internalClientId;
}
