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
      const verificationLink = `${config.APP_URL || 'http://localhost:5010'}/verify-email?token=${token}`;
      await sendTemplatedEmailWithFallback(
        {
          templateKey: 'email_verification',
          variables: {
            userName: opts.displayName || opts.email,
            verificationLink,
            expiresIn: '24 hours',
          },
          to: opts.email,
          userId: user.id,
          clientId: client?.id || null,
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
  const isEmail = identifier.includes('@');

  const user = await prisma.user.findFirst({
    where: isEmail ? { email: identifier } : { OR: [{ username: identifier }, { email: identifier }] },
  });

  if (!user || !user.passwordHash) {
    throw new AppError('Invalid credentials.', 'INVALID_CREDENTIALS', 401);
  }

  const valid = await bcrypt.compare(opts.password, user.passwordHash);
  if (!valid) {
    await writeAuditLog({ userId: user.id, action: 'LOGIN', metadata: { success: false }, req });
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

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId: client?.id ?? (await getOrCreateInternalClientId()),
      tokenHash,
      scopes: ['openid', 'offline_access'],
      expiresAt: buildTokenExpiry(config.REFRESH_TOKEN_TTL),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
    },
  });

  await prisma.loginSession.create({
    data: {
      userId: user.id,
      clientId: client?.id ?? (await getOrCreateInternalClientId()),
      sessionToken: generateOpaqueToken(),
      expiresAt: buildTokenExpiry(config.REFRESH_TOKEN_TTL),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
    },
  });

  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() },
  });

  await writeAuditLog({ userId: user.id, clientId: client?.id, action: 'LOGIN', metadata: { success: true }, req });

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

  await createAdminNotification({
    userId: user.id,
    type: 'LOGIN',
    title: 'New login detected',
    message: `A new sign-in to WPA Central Auth was recorded from ${req.ip ?? 'an unknown IP address'}.`,
    severity: 'SECURITY',
    category: 'AUTH',
    actionUrl: '/sessions',
    metadata: {
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'] ?? null,
    },
  });

  return {
    accessToken,
    refreshToken,
    expiresIn: parseTtlToSeconds(config.ACCESS_TOKEN_TTL),
    user: safeUser(user, roles),
  };
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

export async function refreshTokens(rawRefreshToken: string, req: Request) {
  let payload: { sub: string };
  try {
    payload = verifyRefreshToken(rawRefreshToken);
  } catch {
    throw new AppError('Invalid or expired refresh token.', 'TOKEN_INVALID', 401);
  }

  const tokenHash = hashToken(rawRefreshToken);
  const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });

  if (!stored || stored.revokedAt || stored.expiresAt < new Date()) {
    throw new AppError('Refresh token is invalid or has been revoked.', 'TOKEN_REVOKED', 401);
  }
  if (stored.userId !== payload.sub) {
    throw new AppError('Token mismatch.', 'TOKEN_INVALID', 401);
  }

  const user = await prisma.user.findUnique({ where: { id: payload.sub } });
  if (!user || user.status === UserStatus.DELETED || user.status === UserStatus.SUSPENDED) {
    throw new AppError('User is not active.', 'ACCOUNT_INACTIVE', 403);
  }

  // Rotate: revoke old, issue new
  await prisma.refreshToken.update({ where: { tokenHash }, data: { revokedAt: new Date() } });

  const roles = await getUserRoles(user.id);
  const newAccess = signAccessToken({ sub: user.id, email: user.email, username: user.username, roles });
  const newRefresh = signRefreshToken(user.id);

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId: stored.clientId,
      tokenHash: hashToken(newRefresh),
      scopes: stored.scopes,
      expiresAt: buildTokenExpiry(config.REFRESH_TOKEN_TTL),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
    },
  });

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
  if (rawRefreshToken) {
    const tokenHash = hashToken(rawRefreshToken);
    await prisma.refreshToken.updateMany({
      where: { tokenHash, userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  // Revoke all active sessions for this user (or just the matching one)
  await prisma.loginSession.updateMany({
    where: {
      userId,
      revokedAt: null,
      ipAddress: req.ip ?? req.socket.remoteAddress,
    },
    data: { revokedAt: new Date() },
  });

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
    severity: 'SECURITY',
    category: 'SECURITY',
    actionUrl: '/account',
  });

  const resetLink = `${config.APP_URL || 'http://localhost:5010'}/reset-password?token=${token}`;
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'password_reset',
      variables: {
        resetPasswordLink: resetLink,
        expiresIn: '1 hour',
      },
      to: email,
      userId: user.id,
    },
    'Password Reset Request',
    `You requested a password reset. Click here to reset: ${resetLink}`
  );

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
    severity: 'SECURITY',
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

  const verificationLink = `${config.APP_URL || 'http://localhost:5010'}/verify-email?token=${token}`;
  const requestUser = await prisma.user.findUnique({ where: { id: userId } });
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'email_verification',
      variables: {
        userName: requestUser?.displayName || email,
        verificationLink,
        expiresIn: '24 hours',
      },
      to: email,
      userId,
    },
    'Verify your email',
    `Please verify your email by clicking this link: ${verificationLink}`
  );

  if (process.env.NODE_ENV === 'development') {
    return token;
  }
}

export async function confirmEmailVerification(token: string, req: Request) {
  const tokenHash = hashToken(token);
  const record = await prisma.emailVerificationToken.findUnique({ where: { tokenHash } });

  if (!record || record.usedAt || record.expiresAt < new Date()) {
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
