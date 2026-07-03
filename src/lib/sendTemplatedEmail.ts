/**
 * Centralized Email Sending Service
 * Uses the email template renderer and logs all sends
 */

import { EmailTemplateKey, EmailVariables } from './emailRenderer.types.js';
import { renderEmailTemplate } from './emailRenderer.js';
import type { OtpTemplatePurpose } from '@prisma/client';
import type { Request } from 'express';
import { dispatchEmail } from '../modules/communication/communication.service.js';

interface SendTemplatedEmailInput {
  templateKey: EmailTemplateKey;
  variables: EmailVariables;
  to?: string;
  recipientEmail?: string;
  recipientName?: string;
  clientId?: string | null;
  locale?: string | null;
  purpose?: OtpTemplatePurpose;
  userId?: string | null;
  req?: Request;
  maskSensitiveData?: boolean;
}

interface SendTemplatedEmailResult {
  success: boolean;
  queued?: boolean;
  error?: string;
  sendLogId?: string;
}

/**
 * Mask sensitive values in logs (OTP codes, tokens, etc)
 */
function maskSensitiveValues(variables: EmailVariables): EmailVariables {
  const masked = { ...variables };
  const sensitiveKeys = ['otpCode', 'code', 'token', 'resetToken', 'resetLink', 'magicLink', 'verificationLink', 'inviteLink'];

  for (const key of sensitiveKeys) {
    if (key in masked && typeof masked[key as keyof EmailVariables] === 'string') {
      const value = String(masked[key as keyof EmailVariables]);
      masked[key as keyof EmailVariables] = `***${value.slice(-4)}`;
    }
  }

  return masked;
}

/**
 * Send email using templated renderer with logging
 */
export async function sendTemplatedEmail(
  input: SendTemplatedEmailInput
): Promise<SendTemplatedEmailResult> {
  const purpose = input.purpose || 'GENERAL';
  const maskData = input.maskSensitiveData ?? true;
  const loggedVariables = maskData ? maskSensitiveValues(input.variables) : input.variables;
  const recipientEmail = input.recipientEmail || input.to;

  if (!recipientEmail) {
    return {
      success: false,
      error: 'Recipient email is required',
    };
  }

  try {
    // Render the email template with client and locale context
    const rendered = await renderEmailTemplate(
      input.templateKey,
      input.variables,
      input.clientId,
      input.locale
    );

    // Enqueue the email send. The worker will do the actual provider dispatch.
    const sendResult = await dispatchEmail({
      to: recipientEmail,
      subject: rendered.subject,
      text: rendered.text,
      html: rendered.html,
      purpose,
      clientId: input.clientId,
      senderName: rendered.senderName,
      senderEmail: rendered.senderEmail,
      replyTo: rendered.replyTo,
      templateKey: input.templateKey,
      userId: input.userId ?? null,
      req: input.req,
    });

    return {
      success: true,
      queued: Boolean((sendResult as any).queued ?? true),
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    // Try to get sender info for failed send logging
    let senderName: string | undefined;
    let senderEmail: string | undefined;
    try {
      const rendered = await renderEmailTemplate(
        input.templateKey,
        {},
        input.clientId,
        input.locale
      );
      senderName = rendered.senderName;
      senderEmail = rendered.senderEmail;
    } catch (e) {
      // If we can't render for sender info, continue without it
    }

    return {
      success: false,
      error: errorMessage,
    };
  }
}

/**
 * Send email with fallback to basic text template if rendering fails
 */
export async function sendTemplatedEmailWithFallback(
  input: SendTemplatedEmailInput,
  fallbackSubject: string,
  fallbackBody: string
): Promise<SendTemplatedEmailResult> {
  let primaryError: unknown;
  try {
    const primaryResult = await sendTemplatedEmail(input);
    // sendTemplatedEmail() catches its own render/dispatch errors internally
    // and resolves with { success: false } rather than throwing (see above) —
    // without this check, a bad/missing template variable would never reach
    // the fallback below and the caller would just get a hard failure.
    if (primaryResult.success) {
      return primaryResult;
    }
    primaryError = new Error(primaryResult.error || 'Templated email send failed');
  } catch (error) {
    primaryError = error;
  }

  {
    console.warn(`Falling back to basic email for ${input.templateKey}:`, primaryError);

    const recipientEmail = input.recipientEmail || input.to;
    if (!recipientEmail) {
      return {
        success: false,
        error: 'Recipient email is required',
      };
    }

    try {
      // Try basic send with fallback subject and body
      const purpose = input.purpose || 'GENERAL';
      await dispatchEmail({
        to: recipientEmail,
        subject: fallbackSubject,
        text: fallbackBody,
        html: `<p>${fallbackBody}</p>`,
        purpose,
        userId: input.userId ?? null,
        req: input.req,
      });

      return {
        success: true,
        queued: true,
      };
    } catch (fallbackError) {
      const errorMessage = fallbackError instanceof Error ? fallbackError.message : 'Unknown error';

      return {
        success: false,
        error: errorMessage,
      };
    }
  }
}
