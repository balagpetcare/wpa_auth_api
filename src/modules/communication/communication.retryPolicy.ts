import type { OtpTemplatePurpose } from '@prisma/client';
import { AppError } from '../../lib/errors.js';

// Retry policy for the communication retry/resend center. OTP and any
// link/token-based verification message (email verification, password
// reset, magic link, 2FA/OTP codes, admin invite) is time-sensitive and
// security-sensitive: retrying it later would either resend a stale/expired
// code or silently re-arm an old token, so it is always non-retryable
// regardless of what CommunicationPurpose it maps to for routing.
export const OTP_NON_RETRYABLE = 'OTP_NON_RETRYABLE';
export const RETRYABLE_TRANSACTIONAL = 'RETRYABLE_TRANSACTIONAL';
export const RETRYABLE_ALERT = 'RETRYABLE_ALERT';

export const RETRY_DELAYS_MS = [5 * 60_000, 30 * 60_000, 2 * 60 * 60_000];
export const DEFAULT_MAX_RETRIES = RETRY_DELAYS_MS.length;

export const OTP_NON_RETRYABLE_REASON =
  'OTP/token messages are not retried for security and expiry reasons.';

export interface RetryPolicy {
  isRetryable: boolean;
  retryPolicyKey: string;
  maxRetries: number;
  reason?: string;
}

const NON_RETRYABLE: RetryPolicy = {
  isRetryable: false,
  retryPolicyKey: OTP_NON_RETRYABLE,
  maxRetries: 0,
  reason: OTP_NON_RETRYABLE_REASON,
};

const TRANSACTIONAL_RETRYABLE: RetryPolicy = {
  isRetryable: true,
  retryPolicyKey: RETRYABLE_TRANSACTIONAL,
  maxRetries: DEFAULT_MAX_RETRIES,
};

const ALERT_RETRYABLE: RetryPolicy = {
  isRetryable: true,
  retryPolicyKey: RETRYABLE_ALERT,
  maxRetries: DEFAULT_MAX_RETRIES,
};

// Every templateKey actually sent by this codebase today (see
// lib/emailNotifications.ts and auth.service.ts). This table is the
// authoritative retry decision when a templateKey is known — it is more
// precise than purpose alone, since e.g. `password_reset` and
// `password_changed` both currently dispatch under purpose GENERAL but have
// very different retry safety (one carries a reset token, the other doesn't).
const TEMPLATE_KEY_POLICY: Record<string, RetryPolicy> = {
  email_verification: NON_RETRYABLE, // carries a time-limited verification link
  password_reset: NON_RETRYABLE, // carries a time-limited reset token
  magic_link: NON_RETRYABLE, // carries a one-time passwordless login link
  two_factor_code: NON_RETRYABLE, // numeric OTP code
  otp_login: NON_RETRYABLE, // numeric OTP code
  admin_invitation: NON_RETRYABLE, // carries a time-limited invite token; use the dedicated resend-invite flow instead
  password_changed: TRANSACTIONAL_RETRYABLE,
  welcome: TRANSACTIONAL_RETRYABLE,
  account_reactivated: TRANSACTIONAL_RETRYABLE,
  role_updated: TRANSACTIONAL_RETRYABLE,
  login_alert: ALERT_RETRYABLE,
  security_alert: ALERT_RETRYABLE,
  account_suspended: ALERT_RETRYABLE,
};

// Fallback policy by CommunicationDeliveryLog.purpose (OtpTemplatePurpose)
// for sends that don't carry a known templateKey (e.g. direct
// dispatchEmail/dispatchSms callers, sendOtpEmail/sendOtpSms/test sends).
const PURPOSE_POLICY: Record<OtpTemplatePurpose, RetryPolicy> = {
  LOGIN: NON_RETRYABLE,
  REGISTER: NON_RETRYABLE,
  PASSWORD_RESET: NON_RETRYABLE,
  PAYMENT_VERIFY: NON_RETRYABLE,
  ADMIN_INVITE: NON_RETRYABLE,
  GENERAL: TRANSACTIONAL_RETRYABLE,
};

export function resolveRetryPolicy(templateKey: string | undefined | null, purpose: OtpTemplatePurpose): RetryPolicy {
  if (templateKey && TEMPLATE_KEY_POLICY[templateKey]) {
    return TEMPLATE_KEY_POLICY[templateKey];
  }
  const purposePolicy = PURPOSE_POLICY[purpose];
  if (!purposePolicy) {
    // Defensive: every OtpTemplatePurpose enum value must be classified
    // above. An unrecognized value here means the schema added a new
    // purpose without a retry-policy decision — fail loudly rather than
    // silently guessing (and never silently default to OTP/retryable).
    throw new AppError(`No retry policy configured for communication purpose: ${purpose}`, 'VALIDATION_ERROR', 400);
  }
  return purposePolicy;
}

export function getRetryDelayMs(retryCount: number): number {
  return RETRY_DELAYS_MS[Math.min(retryCount, RETRY_DELAYS_MS.length - 1)];
}
