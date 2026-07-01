import nodemailer from 'nodemailer';
import { AppError } from '../../lib/errors.js';
import type { EmailSendInput, ProviderSendResult, SmsSendInput } from './communication.types.js';

export interface SmsProviderAdapter {
  sendSms(input: SmsSendInput): Promise<ProviderSendResult>;
}

export interface EmailProviderAdapter {
  sendEmail(input: EmailSendInput): Promise<ProviderSendResult>;
}

class GenericHttpSmsAdapter implements SmsProviderAdapter {
  async sendSms(input: SmsSendInput): Promise<ProviderSendResult> {
    const method = (input.credentials['method'] || 'POST').toUpperCase();
    const endpointTemplate = input.credentials['endpoint'] || input.credentials['apiUrl'] || input.credentials['url'];
    if (!endpointTemplate) {
      return { success: false, errorCode: 'SMS_CONFIG_MISSING', errorMessage: 'SMS endpoint is not configured.' };
    }

    const senderId = input.credentials['senderId'] || '';
    const apiKey = input.credentials['apiKey'] || input.credentials['api_key'] || '';
    const token = input.credentials['token'] || '';

    // Interpolate variables in endpoint URL
    let endpoint = endpointTemplate
      .replace('{{to}}', encodeURIComponent(input.to))
      .replace('{{phone}}', encodeURIComponent(input.to))
      .replace('{{message}}', encodeURIComponent(input.message))
      .replace('{{senderId}}', encodeURIComponent(senderId))
      .replace('{{apiKey}}', encodeURIComponent(apiKey))
      .replace('{{token}}', encodeURIComponent(token));

    // Custom headers from credentials
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (input.credentials['headers']) {
      try {
        const customHeaders = typeof input.credentials['headers'] === 'string'
          ? JSON.parse(input.credentials['headers'])
          : input.credentials['headers'];
        Object.assign(headers, customHeaders);
      } catch {
        // Ignore JSON parse errors
      }
    }

    // Additional authentication headers if specified
    if (input.credentials['authHeaderName'] && input.credentials['authHeaderValue']) {
      headers[input.credentials['authHeaderName']] = input.credentials['authHeaderValue'];
    }

    // Body payload mapping
    const payload: Record<string, any> = {
      to: input.to,
      phone: input.to,
      message: input.message,
      senderId,
      apiKey,
      token,
    };

    // If method is GET, append params to endpoint if not interpolated
    if (method === 'GET') {
      const urlObj = new URL(endpoint);
      Object.entries(payload).forEach(([key, val]) => {
        if (val && !endpointTemplate.includes(`{{${key}}}`)) {
          urlObj.searchParams.set(key, String(val));
        }
      });
      endpoint = urlObj.toString();
    }

    const controller = new AbortController();
    const timeoutVal = Number(input.credentials['timeout'] || 10000);
    const timeoutId = setTimeout(() => controller.abort(), timeoutVal);

    try {
      const requestOptions: RequestInit = {
        method,
        headers,
        signal: controller.signal,
      };

      if (method !== 'GET') {
        const contentType = headers['Content-Type'] || 'application/json';
        if (contentType.includes('application/x-www-form-urlencoded')) {
          const formBody = new URLSearchParams();
          Object.entries(payload).forEach(([key, val]) => {
            formBody.append(key, String(val));
          });
          requestOptions.body = formBody;
        } else {
          requestOptions.body = JSON.stringify(payload);
        }
      }

      const res = await fetch(endpoint, requestOptions);
      clearTimeout(timeoutId);

      const responseText = await res.text();
      let responseData: Record<string, any> = {};
      try {
        responseData = JSON.parse(responseText);
      } catch {
        responseData = { rawText: responseText };
      }

      if (!res.ok) {
        return {
          success: false,
          rawResponse: responseData,
          errorCode: `HTTP_${res.status}`,
          errorMessage: 'SMS provider request failed. Please check delivery logs for raw response details.',
        };
      }

      // Check success code / flag if configured
      let isSuccess = true;
      const successKey = input.credentials['successKey'];
      const successValue = input.credentials['successValue'];
      if (successKey) {
        const actualVal = responseData[successKey];
        if (successValue !== undefined) {
          isSuccess = String(actualVal) === String(successValue);
        } else {
          isSuccess = Boolean(actualVal);
        }
      }

      return {
        success: isSuccess,
        providerMessageId: responseData.messageId || responseData.id || null,
        rawResponse: responseData,
        errorCode: isSuccess ? null : 'PROVIDER_ERROR_FLAG',
        errorMessage: isSuccess ? null : 'SMS provider indicated transaction failure.',
      };

    } catch (error: any) {
      clearTimeout(timeoutId);
      const isAbort = error?.name === 'AbortError';
      return {
        success: false,
        rawResponse: { error: error?.message || 'SMS error occurred' },
        errorCode: isAbort ? 'TIMEOUT' : 'SMS_NETWORK_ERROR',
        errorMessage: isAbort ? 'SMS provider request timed out.' : 'SMS provider network transaction failed.',
      };
    }
  }
}

class GenericSmtpEmailAdapter implements EmailProviderAdapter {
  async sendEmail(input: EmailSendInput): Promise<ProviderSendResult> {
    const username = input.credentials['username'];
    const password = input.credentials['password'];
    if (!input.config.smtpHost || !input.config.smtpPort || !username || !password || !input.config.fromEmail) {
      return { success: false, errorCode: 'EMAIL_CONFIG_MISSING', errorMessage: 'SMTP provider configuration is incomplete.' };
    }

    const transporter = nodemailer.createTransport({
      host: input.config.smtpHost,
      port: input.config.smtpPort,
      secure: Boolean(input.config.smtpSecure),
      auth: { user: username, pass: password },
      connectionTimeout: 10000, // 10s connection timeout
      greetingTimeout: 10000,   // 10s greeting timeout
      socketTimeout: 15000,     // 15s socket timeout
    });

    try {
      const info = await transporter.sendMail({
        from: input.config.fromName ? `${input.config.fromName} <${input.config.fromEmail}>` : input.config.fromEmail,
        to: input.to,
        subject: input.subject,
        text: input.text,
        html: input.html,
      });
      return {
        success: true,
        providerMessageId: info.messageId,
        rawResponse: {
          accepted: info.accepted,
          rejected: info.rejected,
          envelope: info.envelope,
        },
      };
    } catch (error: any) {
      return {
        success: false,
        errorCode: 'SMTP_SEND_FAILED',
        errorMessage: 'SMTP email send failed. Please verify provider credentials and configuration.',
        rawResponse: { error: error?.message || 'SMTP error occurred' },
      };
    }
  }
}

const genericHttpSmsAdapter = new GenericHttpSmsAdapter();
const genericSmtpEmailAdapter = new GenericSmtpEmailAdapter();

export function resolveSmsAdapter(providerCode: string): SmsProviderAdapter {
  if (providerCode) return genericHttpSmsAdapter;
  throw new AppError('Unknown SMS provider adapter.', 'BAD_REQUEST', 400);
}

export function resolveEmailAdapter(providerCode: string): EmailProviderAdapter {
  if (providerCode) return genericSmtpEmailAdapter;
  throw new AppError('Unknown email provider adapter.', 'BAD_REQUEST', 400);
}
