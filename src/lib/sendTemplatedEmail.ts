/**
 * Centralized Email Sending Service
 * Uses the email template renderer and logs all sends
 */

import { EmailTemplateKey, EmailVariables } from './emailRenderer.types.js';
import { renderEmailTemplate } from './emailRenderer.js';
import { dispatchEmail } from '../modules/communication/communication.service.js';
import { prisma } from './db.js';
import type { OtpTemplatePurpose } from '@prisma/client';

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
  maskSensitiveData?: boolean;
}

interface SendTemplatedEmailResult {
  success: boolean;
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

    // Send the email with client-specific sender info
    const sendResult = await dispatchEmail({
      to: recipientEmail,
      subject: rendered.subject,
      text: rendered.text,
      html: rendered.html,
      purpose,
      clientId: input.clientId,
      senderName: rendered.senderName,
      senderEmail: rendered.senderEmail,
    });

    // Log successful send with all context
    const logData: any = {
      templateKey: input.templateKey,
      locale: input.locale || 'en',
      clientId: input.clientId ?? null,
      recipientEmail,
      subject: rendered.subject,
      variables: loggedVariables as any,
      status: 'sent',
      deliveryStatus: 'sent',
      userId: input.userId ?? null,
      senderName: rendered.senderName,
      senderEmail: rendered.senderEmail,
      sentAt: new Date(),
    };
    if (input.recipientName) {
      logData.recipientName = input.recipientName;
    }

    // Safely log provider response without exposing sensitive data
    if (sendResult.rawResponse) {
      const response = sendResult.rawResponse as any;
      logData.providerResponse = {
        messageId: response.messageId,
        status: response.status,
        timestamp: response.timestamp,
        // Don't log full response - just essential fields
      };
    }

    const log = await prisma.emailSendLog.create({
      data: logData,
    });

    return {
      success: true,
      sendLogId: log.id,
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

    // Log failed send with context
    try {
      const logData: any = {
        templateKey: input.templateKey,
        locale: input.locale || 'en',
        clientId: input.clientId ?? null,
        recipientEmail,
        subject: `[FAILED] ${input.templateKey}`,
        variables: loggedVariables as any,
        status: 'failed',
        deliveryStatus: 'failed',
        userId: input.userId ?? null,
        errorMessage,
        failedAt: new Date(),
      };
      if (senderName) logData.senderName = senderName;
      if (senderEmail) logData.senderEmail = senderEmail;
      if (input.recipientName) logData.recipientName = input.recipientName;

      const log = await prisma.emailSendLog.create({
        data: logData,
      });

      return {
        success: false,
        error: errorMessage,
        sendLogId: log.id,
      };
    } catch (logError) {
      console.error('Failed to log email send attempt:', logError);
      return {
        success: false,
        error: errorMessage,
      };
    }
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
  try {
    return await sendTemplatedEmail(input);
  } catch (error) {
    console.warn(`Falling back to basic email for ${input.templateKey}:`, error);

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
      });

      // Log the fallback send
      const maskData = input.maskSensitiveData ?? true;
      const loggedVariables = maskData ? maskSensitiveValues(input.variables) : input.variables;
      const logData: any = {
        templateKey: input.templateKey,
        recipientEmail,
        subject: `[FALLBACK] ${fallbackSubject}`,
        variables: loggedVariables as any,
        status: 'SUCCESS_FALLBACK',
        userId: input.userId ?? null,
        errorMessage: `Template render failed, used fallback: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };

      await prisma.emailSendLog.create({
        data: logData,
      });

      return {
        success: true,
      };
    } catch (fallbackError) {
      const errorMessage = fallbackError instanceof Error ? fallbackError.message : 'Unknown error';

      try {
        const maskData = input.maskSensitiveData ?? true;
        const loggedVariables = maskData ? maskSensitiveValues(input.variables) : input.variables;
        const logData: any = {
          templateKey: input.templateKey,
          recipientEmail,
          subject: `[FAILED] ${fallbackSubject}`,
          variables: loggedVariables as any,
          status: 'FAILED',
          userId: input.userId ?? null,
          errorMessage: `Both template and fallback failed: ${errorMessage}`,
        };

        await prisma.emailSendLog.create({
          data: logData,
        });
      } catch (logError) {
        console.error('Failed to log fallback email failure:', logError);
      }

      return {
        success: false,
        error: errorMessage,
      };
    }
  }
}
