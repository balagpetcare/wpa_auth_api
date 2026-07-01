import type { OtpTemplatePurpose } from '@prisma/client';
import { dispatchEmail } from '../modules/communication/communication.service.js';

export async function sendEmail(
  to: string,
  subject: string,
  text: string,
  html?: string,
  purpose: OtpTemplatePurpose = 'GENERAL',
  clientId?: string | null,
  senderName?: string | null,
  senderEmail?: string | null,
) {
  return dispatchEmail({
    to,
    subject,
    text,
    html,
    purpose,
    clientId,
    senderName,
    senderEmail,
  });
}
