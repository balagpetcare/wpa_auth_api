/**
 * Email Notification Service
 * High-level functions for sending specific notification emails
 * Uses the centralized template renderer
 */

import { sendTemplatedEmailWithFallback } from './sendTemplatedEmail.js';

/**
 * Send welcome email to newly verified users
 */
export async function sendWelcomeEmail(
  email: string,
  userName: string,
  userId: string,
  clientId?: string | null,
): Promise<void> {
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'welcome',
      variables: {
        userName,
      },
      to: email,
      userId,
      clientId,
    },
    'Welcome to WPA Central Auth',
    `Welcome ${userName}! Your account is ready to use.`
  );
}

/**
 * Send login alert notification
 */
export async function sendLoginAlertEmail(
  email: string,
  userName: string,
  ipAddress: string | null,
  userAgent: string | null,
  userId: string,
  clientId?: string | null,
): Promise<void> {
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'login_alert',
      variables: {
        userName,
        ipAddress: ipAddress || 'Unknown',
        userAgent: userAgent || 'Unknown device',
        timestamp: new Date().toISOString(),
      },
      to: email,
      userId,
      clientId,
    },
    'New login detected',
    `A new login to your account was detected from ${ipAddress || 'an unknown location'}.`
  );
}

/**
 * Send security alert for suspicious activity
 */
export async function sendSecurityAlertEmail(
  email: string,
  userName: string,
  alertType: string,
  details: string,
  userId: string,
): Promise<void> {
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'security_alert',
      variables: {
        userName,
        alertType,
        details,
      },
      to: email,
      userId,
    },
    'Security Alert - Action Required',
    `Alert: ${alertType}. Details: ${details}`
  );
}

/**
 * Send account suspended notification
 */
export async function sendAccountSuspendedEmail(
  email: string,
  userName: string,
  reason: string,
  userId: string,
): Promise<void> {
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'account_suspended',
      variables: {
        userName,
        reason,
      },
      to: email,
      userId,
    },
    'Your account has been suspended',
    `Your account has been suspended. Reason: ${reason}`
  );
}

/**
 * Send account reactivated notification
 */
export async function sendAccountReactivatedEmail(
  email: string,
  userName: string,
  userId: string,
): Promise<void> {
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'account_reactivated',
      variables: {
        userName,
      },
      to: email,
      userId,
    },
    'Your account has been reactivated',
    `Your account has been reactivated and is ready to use.`
  );
}

/**
 * Send role/permission update notification
 */
export async function sendRoleUpdatedEmail(
  email: string,
  userName: string,
  changes: string,
  userId: string,
): Promise<void> {
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'role_updated',
      variables: {
        userName,
        changes,
      },
      to: email,
      userId,
    },
    'Your permissions have been updated',
    `Your account permissions were updated. Changes: ${changes}`
  );
}

/**
 * Send magic link for passwordless authentication
 */
export async function sendMagicLinkEmail(
  email: string,
  magicLink: string,
  expiresIn: string = '15 minutes',
): Promise<void> {
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'magic_link',
      variables: {
        magicLink,
        expiresIn,
      },
      to: email,
    },
    'Your passwordless login link',
    `Use this link to login: ${magicLink}. This link expires in ${expiresIn}.`
  );
}

/**
 * Send two-factor authentication code
 */
export async function sendTwoFactorCodeEmail(
  email: string,
  code: string,
  expiresIn: string = '10 minutes',
  userId: string,
): Promise<void> {
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'two_factor_code',
      variables: {
        code,
        expiresIn,
      },
      to: email,
      userId,
    },
    'Your two-factor authentication code',
    `Your authentication code is: ${code}. This code expires in ${expiresIn}.`
  );
}

/**
 * Send OTP code for various purposes (login, password reset, etc)
 */
export async function sendOtpCodeEmail(
  email: string,
  code: string,
  purpose: string,
  expiresIn: string = '10 minutes',
  userId?: string,
): Promise<void> {
  await sendTemplatedEmailWithFallback(
    {
      templateKey: 'otp_login',
      variables: {
        code,
        expiresIn,
        purpose,
      },
      to: email,
      userId: userId || null,
    },
    `Your ${purpose} code`,
    `Your code is: ${code}. This code expires in ${expiresIn}.`
  );
}
