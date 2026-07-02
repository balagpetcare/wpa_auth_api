/**
 * Email Template Rendering Service
 * Renders email templates with variable substitution, branding, and security
 */

import { prisma } from './db.js';
import { escapeHtml, escapeAttribute, isValidEmailUrl, sanitizeHtml } from './htmlSanitizer.js';
import { DEFAULT_EMAIL_TEMPLATES } from './defaultEmailTemplates.js';
import {
  EmailTemplateKey,
  EmailVariables,
  RenderEmailTemplateInput,
  RenderedEmail,
  EmailBrandingData,
  EmailTemplateData,
  VariableValidationResult,
  ResolvedSenderInfo,
} from './emailRenderer.types.js';

// Default branding fallbacks — non-secret, hardcoded. This is the final
// fallback tier when no DB EmailBrandingSetting/ClientBranding row applies;
// it must never be replaced with ENV-sourced values (product policy: ENV
// holds only system-level secrets, not identity/branding data).
const DEFAULT_BRANDING: Partial<EmailBrandingData> = {
  brandName: 'World Pet Association',
  primaryColor: '#0f3a7d',
  textColor: '#333333',
  headerBackgroundColor: '#0f3a7d',
  footerBackgroundColor: '#f5f5f5',
  supportEmail: 'support@worldpetassociation.org',
  websiteUrl: 'https://worldpetassociation.org',
  privacyUrl: 'https://worldpetassociation.org/privacy',
  termsUrl: 'https://worldpetassociation.org/terms',
  contactUrl: 'https://worldpetassociation.org/contact',
  legalDisclaimer: 'This is an automated message. Please do not reply directly to this email.',
};

const DEFAULT_SENDER_NAME = DEFAULT_BRANDING.brandName as string;
const DEFAULT_SENDER_EMAIL = 'noreply@worldpetassociation.org';

// Global variables available in all templates
const GLOBAL_VARIABLES = [
  'brandName',
  'supportEmail',
  'supportPhone',
  'websiteUrl',
  'privacyUrl',
  'termsUrl',
  'helpUrl',
  'contactUrl',
  'legalDisclaimer',
];

/**
 * Main function to render an email template
 * Loads branding, template, substitutes variables, and returns rendered email
 *
 * Template/Branding Resolution Priority:
 * 1. clientId + templateKey + requested locale
 * 2. clientId + templateKey + en (if locale not en)
 * 3. global + templateKey + requested locale
 * 4. global + templateKey + en
 * 5. DEFAULT_EMAIL_TEMPLATES built-in template
 *
 * Sender Resolution Priority:
 * 1. ClientBranding.senderName/senderEmail/replyTo if clientId provided
 * 2. EmailBrandingSetting.senderName/senderEmail/replyTo (global)
 * 3. Fallback: DEFAULT_BRANDING constant (non-secret, hardcoded — see
 *    Phase 2.6A, docs/phase-2-6a-app-aware-communication-routing-ui.md).
 *    Credentials must never live in ENV per product policy; this fallback
 *    used to read process.env.SMTP_FROM_NAME/SMTP_FROM_EMAIL directly,
 *    bypassing both the DB branding system and the validated config
 *    schema — removed.
 */
export async function renderEmailTemplate(
  templateKey: EmailTemplateKey,
  variables: EmailVariables,
  clientId?: string | null,
  locale?: string | null
): Promise<RenderedEmail & ResolvedSenderInfo> {
  try {
    const normalizedLocale = locale || 'en';

    // Load branding, template, and sender info in parallel
    const [branding, template, senderInfo] = await Promise.all([
      getEmailBrandingWithClientFallback(clientId),
      getEmailTemplateByKey(templateKey, normalizedLocale, clientId),
      getEmailSenderInfo(clientId),
    ]);

    if (!template) {
      throw new Error(`Email template not found: ${templateKey} (client: ${clientId}, locale: ${normalizedLocale})`);
    }

    // Merge branding into variables for substitution
    const mergedVariables = mergeVariables(variables, branding);

    // Validate variables against template schema
    const validation = validateVariables(mergedVariables, template);
    if (!validation.isValid) {
      throw new Error(`Invalid email variables: ${validation.errors.join('; ')}`);
    }

    // Substitute variables in template content
    const subject = substituteVariables(template.subject, mergedVariables);
    const preheader = substituteVariables(template.preheader || '', mergedVariables);
    let html = substituteVariables(template.htmlBody, mergedVariables);
    let text = substituteVariables(template.textBody || '', mergedVariables);

    // Inject header and footer
    html = injectEmailHeader(html, branding) + html + injectEmailFooter(html, branding);

    return {
      subject,
      preheader,
      html: sanitizeHtml(html),
      text,
      senderName: senderInfo.senderName,
      senderEmail: senderInfo.senderEmail,
      replyTo: senderInfo.replyTo,
    };
  } catch (error) {
    // Log error without exposing sensitive data
    console.error(`Email rendering failed for template: ${templateKey}`, {
      error: error instanceof Error ? error.message : 'Unknown error',
      clientId,
      locale,
      variableKeys: Object.keys(variables || {}),
    });
    throw error;
  }
}

/**
 * Loads the active email branding settings from database
 */
async function getActiveEmailBranding(): Promise<EmailBrandingData> {
  try {
    const branding = await prisma.emailBrandingSetting.findFirst({
      where: { isActive: true },
    });

    if (!branding) {
      return DEFAULT_BRANDING as EmailBrandingData;
    }

    return branding;
  } catch (error) {
    console.warn('Failed to load email branding, using defaults', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return DEFAULT_BRANDING as EmailBrandingData;
  }
}

/**
 * Loads email branding with client-aware fallback:
 * 1. ClientBranding for clientId (if exists)
 * 2. Global EmailBrandingSetting
 * 3. DEFAULT_BRANDING fallback
 */
async function getEmailBrandingWithClientFallback(clientId?: string | null): Promise<EmailBrandingData> {
  try {
    // Try client-specific branding first
    if (clientId) {
      const clientBranding = await prisma.clientBranding.findUnique({
        where: { clientId },
      });

      if (clientBranding && clientBranding.isActive) {
        // Merge client branding with defaults for missing fields
        return {
          ...DEFAULT_BRANDING,
          ...(clientBranding as any),
          brandName: clientBranding.senderName || DEFAULT_BRANDING.brandName,
        } as EmailBrandingData;
      }
    }

    // Fall back to global branding
    return getActiveEmailBranding();
  } catch (error) {
    console.warn(`Failed to load client branding for ${clientId}, using global defaults`, {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return getActiveEmailBranding();
  }
}

/**
 * Resolves sender name, email, and reply-to with fallback chain:
 * 1. ClientBranding.senderName/senderEmail/replyTo (if clientId provided)
 * 2. EmailBrandingSetting.senderName/senderEmail/replyTo (global)
 * 3. DEFAULT_SENDER_NAME / DEFAULT_SENDER_EMAIL constants (non-secret,
 *    hardcoded — see Phase 2.6A). No ENV fallback: credentials/identity
 *    values must not live in ENV per product policy.
 */
async function getEmailSenderInfo(clientId?: string | null): Promise<ResolvedSenderInfo> {
  const defaults: ResolvedSenderInfo = { senderName: DEFAULT_SENDER_NAME, senderEmail: DEFAULT_SENDER_EMAIL, replyTo: null };

  try {
    // Try client-specific sender first
    if (clientId) {
      const clientBranding = await prisma.clientBranding.findUnique({
        where: { clientId },
      });

      if (clientBranding?.isActive) {
        return {
          senderName: clientBranding.senderName || defaults.senderName,
          senderEmail: clientBranding.senderEmail || defaults.senderEmail,
          replyTo: (clientBranding as any).replyTo ?? null,
        };
      }
    }

    // Try global branding sender
    const globalBranding = await prisma.emailBrandingSetting.findFirst({
      where: { isActive: true },
    });

    if (globalBranding) {
      return {
        senderName: (globalBranding as any).senderName || defaults.senderName,
        senderEmail: (globalBranding as any).senderEmail || defaults.senderEmail,
        replyTo: (globalBranding as any).replyTo ?? null,
      };
    }

    return defaults;
  } catch (error) {
    console.warn('Failed to resolve sender info, using non-secret defaults', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    return defaults;
  }
}

/**
 * Loads an email template by key with client-aware fallback chain:
 * 1. clientId + templateKey + locale
 * 2. clientId + templateKey + en (if locale != en)
 * 3. global + templateKey + locale
 * 4. global + templateKey + en
 * 5. DEFAULT_EMAIL_TEMPLATES (built-in)
 */
async function getEmailTemplateByKey(
  templateKey: EmailTemplateKey,
  locale = 'en',
  clientId?: string | null
): Promise<EmailTemplateData | null> {
  try {
    // Try 1: clientId + templateKey + locale
    if (clientId) {
      const template = await prisma.emailTemplate.findFirst({
        where: { key: templateKey, locale, clientId },
      });
      if (template) return convertTemplate(template);
    }

    // Try 2: clientId + templateKey + en (if locale != en)
    if (clientId && locale !== 'en') {
      const template = await prisma.emailTemplate.findFirst({
        where: { key: templateKey, locale: 'en', clientId },
      });
      if (template) return convertTemplate(template);
    }

    // Try 3: global + templateKey + locale
    {
      const template = await prisma.emailTemplate.findFirst({
        where: { key: templateKey, locale, clientId: null },
      });
      if (template) return convertTemplate(template);
    }

    // Try 4: global + templateKey + en (if locale != en)
    if (locale !== 'en') {
      const template = await prisma.emailTemplate.findFirst({
        where: { key: templateKey, locale: 'en', clientId: null },
      });
      if (template) return convertTemplate(template);
    }

    // Try 5: DEFAULT_EMAIL_TEMPLATES (built-in fallback)
    const defaultTemplate = DEFAULT_EMAIL_TEMPLATES.find((t: any) => t.key === templateKey);
    if (defaultTemplate) {
      return {
        id: `default-${defaultTemplate.key}`,
        key: defaultTemplate.key,
        name: defaultTemplate.name,
        subject: defaultTemplate.subject,
        preheader: defaultTemplate.preheader,
        htmlBody: defaultTemplate.htmlBody,
        textBody: defaultTemplate.textBody,
        variables: defaultTemplate.variables as any,
      };
    }

    return null;
  } catch (error) {
    console.error(`Failed to load email template: ${templateKey}`, {
      error: error instanceof Error ? error.message : 'Unknown error',
      clientId,
      locale,
    });
    return null;
  }
}

function convertTemplate(template: any): EmailTemplateData {
  return {
    id: template.id,
    key: template.key,
    name: template.name,
    subject: template.subject,
    preheader: template.preheader,
    htmlBody: template.htmlBody,
    textBody: template.textBody,
    variables: template.variables as any,
  };
}

/**
 * Merges user variables with branding data
 * User variables take precedence over branding
 */
function mergeVariables(
  userVariables: EmailVariables,
  branding: EmailBrandingData
): Record<string, any> {
  const merged: Record<string, any> = {};

  // Add branding variables first (lower priority)
  merged.brandName = branding.brandName || DEFAULT_BRANDING.brandName;
  merged.supportEmail = branding.supportEmail || DEFAULT_BRANDING.supportEmail;
  merged.supportPhone = branding.supportPhone;
  merged.websiteUrl = branding.websiteUrl || DEFAULT_BRANDING.websiteUrl;
  merged.privacyUrl = branding.privacyUrl || DEFAULT_BRANDING.privacyUrl;
  merged.termsUrl = branding.termsUrl || DEFAULT_BRANDING.termsUrl;
  merged.helpUrl = branding.helpUrl;
  merged.contactUrl = branding.contactUrl || DEFAULT_BRANDING.contactUrl;
  merged.legalDisclaimer = branding.legalDisclaimer || DEFAULT_BRANDING.legalDisclaimer;

  // Add user variables (higher priority, overwrites branding)
  for (const [key, value] of Object.entries(userVariables)) {
    if (value !== null && value !== undefined) {
      merged[key] = value;
    }
  }

  return merged;
}

/**
 * Validates that all required variables are provided
 */
function validateVariables(
  variables: Record<string, any>,
  template: EmailTemplateData
): VariableValidationResult {
  const errors: string[] = [];
  const missing: string[] = [];

  if (!template.variables) {
    return { isValid: true, missing: [], errors: [] };
  }

  const requiredVars = (template.variables as any).required || [];

  for (const required of requiredVars) {
    if (!variables.hasOwnProperty(required) || variables[required] == null) {
      missing.push(required);
      errors.push(`Missing required variable: ${required}`);
    }
  }

  return {
    isValid: errors.length === 0,
    missing,
    errors,
  };
}

/**
 * Substitutes {{variable}} placeholders with values
 * Handles OTP code special formatting
 * Removes unreplaced optional variables
 */
function substituteVariables(template: string, variables: Record<string, any>): string {
  if (!template || typeof template !== 'string') {
    return '';
  }

  let result = template;

  // Replace all {{variable}} patterns
  for (const [key, value] of Object.entries(variables)) {
    if (value == null) {
      continue;
    }

    const pattern = new RegExp(`\\{\\{${escapeRegex(key)}\\}\\}`, 'g');
    const stringValue = String(value);

    // Special handling for OTP codes - ensure they're visible
    if (key.toLowerCase().includes('code') && stringValue.length <= 10) {
      // OTP code handling - already formatted in template
      result = result.replace(pattern, escapeHtml(stringValue));
    } else if (key.toLowerCase().includes('link') && isValidEmailUrl(stringValue)) {
      // Valid link - don't escape, let template handle it
      result = result.replace(pattern, stringValue);
    } else {
      // Regular text - escape for safety
      result = result.replace(pattern, escapeHtml(stringValue));
    }
  }

  // Remove any unreplaced optional variables
  result = result.replace(/\{\{[^}]+\}\}/g, '');

  return result;
}

/**
 * Escapes special regex characters in a string
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Injects a professional WPA header into the email
 */
function injectEmailHeader(originalHtml: string, branding: EmailBrandingData): string {
  const brandName = escapeHtml(branding.brandName || DEFAULT_BRANDING.brandName || 'WPA');
  const primaryColor = branding.primaryColor || DEFAULT_BRANDING.primaryColor || '#0f3a7d';
  const headerBgColor = branding.headerBackgroundColor || primaryColor;
  const logoUrl = branding.logoUrl ? escapeAttribute(branding.logoUrl) : '';
  const logoAlt = branding.logoAltText ? escapeAttribute(branding.logoAltText) : 'Logo';

  if (!logoUrl) {
    // Header without logo
    return `
      <table width="100%" cellpadding="0" cellspacing="0" style="background-color: ${escapeAttribute(headerBgColor)}; color: white;">
        <tr>
          <td style="padding: 30px 20px; text-align: center;">
            <h1 style="margin: 0; font-size: 28px; font-weight: 600; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
              ${brandName}
            </h1>
          </td>
        </tr>
      </table>
    `;
  }

  // Header with logo
  return `
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: ${escapeAttribute(headerBgColor)}; color: white;">
      <tr>
        <td style="padding: 20px; text-align: center;">
          <img src="${logoUrl}" alt="${logoAlt}" style="max-width: 200px; height: auto; display: inline-block;" />
        </td>
      </tr>
    </table>
  `;
}

/**
 * Injects a professional WPA footer into the email
 */
function injectEmailFooter(originalHtml: string, branding: EmailBrandingData): string {
  const footerBgColor = branding.footerBackgroundColor || DEFAULT_BRANDING.footerBackgroundColor || '#f5f5f5';
  const textColor = branding.textColor || DEFAULT_BRANDING.textColor || '#333333';
  const disclaimer = escapeHtml(branding.legalDisclaimer || DEFAULT_BRANDING.legalDisclaimer || '');
  const privacyUrl = escapeAttribute(branding.privacyUrl || DEFAULT_BRANDING.privacyUrl || '');
  const termsUrl = escapeAttribute(branding.termsUrl || DEFAULT_BRANDING.termsUrl || '');
  const contactUrl = escapeAttribute(branding.contactUrl || DEFAULT_BRANDING.contactUrl || '');
  const footerText = escapeHtml(branding.footerText || `© ${new Date().getFullYear()} ${branding.brandName || 'World Pet Association'}. All rights reserved.`);

  let footerLinks = '';
  if (isValidEmailUrl(privacyUrl)) {
    footerLinks += `<a href="${privacyUrl}" style="color: #0f3a7d; text-decoration: none; margin: 0 10px;">Privacy Policy</a>`;
  }
  if (isValidEmailUrl(termsUrl)) {
    footerLinks += `<a href="${termsUrl}" style="color: #0f3a7d; text-decoration: none; margin: 0 10px;">Terms of Service</a>`;
  }
  if (isValidEmailUrl(contactUrl)) {
    footerLinks += `<a href="${contactUrl}" style="color: #0f3a7d; text-decoration: none; margin: 0 10px;">Contact Us</a>`;
  }

  return `
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: ${escapeAttribute(footerBgColor)}; border-top: 1px solid #e0e0e0;">
      <tr>
        <td style="padding: 20px; text-align: center; font-size: 12px; color: ${escapeAttribute(textColor)}; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
          <p style="margin: 0 0 10px 0;">${disclaimer}</p>
          <p style="margin: 0 0 10px 0;">
            ${footerLinks}
          </p>
          <p style="margin: 0;">
            ${footerText}
          </p>
        </td>
      </tr>
    </table>
  `;
}

/**
 * Renders an OTP code in a large, readable box for email
 * This is a helper function for templates that need OTP display
 */
export function renderOtpCodeBox(code: string, expiresIn?: string | number): string {
  const displayCode = escapeHtml(String(code).toUpperCase());
  const expiresText = expiresIn ? escapeHtml(`Expires in ${expiresIn} ${typeof expiresIn === 'number' ? 'seconds' : ''}`) : '';

  return `
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; border-left: 4px solid #ff6c2f; margin: 20px 0;">
      <tr>
        <td style="padding: 20px; text-align: center;">
          <div style="font-size: 40px; font-weight: bold; letter-spacing: 6px; color: #0f3a7d; font-family: 'Courier New', monospace; margin: 0;">
            ${displayCode}
          </div>
          ${expiresText ? `<div style="color: #666; font-size: 14px; margin-top: 10px;">⏰ ${expiresText}</div>` : ''}
        </td>
      </tr>
    </table>
  `;
}

/**
 * Renders a CTA button/link for email
 * This is a helper function for templates that need action buttons
 */
export function renderCtaButton(text: string, href: string, variant: 'primary' | 'danger' | 'secondary' = 'primary'): string {
  if (!isValidEmailUrl(href)) {
    // Invalid URL - render as text instead
    return `<p style="margin: 20px 0; text-align: center;">${escapeHtml(text)}</p>`;
  }

  const colors = {
    primary: { bg: '#0f3a7d', text: 'white' },
    danger: { bg: '#d9534f', text: 'white' },
    secondary: { bg: '#666666', text: 'white' },
  };

  const color = colors[variant];
  const escapedHref = escapeAttribute(href);
  const escapedText = escapeHtml(text);

  return `
    <table width="100%" cellpadding="0" cellspacing="0" style="margin: 20px 0;">
      <tr>
        <td style="text-align: center;">
          <a href="${escapedHref}" style="
            display: inline-block;
            background-color: ${color.bg};
            color: ${color.text};
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: 600;
            font-size: 16px;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          ">
            ${escapedText}
          </a>
        </td>
      </tr>
    </table>
  `;
}

/**
 * Helper to safely render a block of information
 */
export function renderInfoBlock(title: string, content: string, variant: 'info' | 'warning' | 'success' = 'info'): string {
  const colors = {
    info: { bg: '#f0f8ff', border: '#b3dce8', text: '#333333' },
    warning: { bg: '#fff3cd', border: '#ffc107', text: '#856404' },
    success: { bg: '#dff0d8', border: '#d6e9c6', text: '#3c763d' },
  };

  const color = colors[variant];
  const escapedTitle = escapeHtml(title);
  const escapedContent = escapeHtml(content);

  return `
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: ${color.bg}; border-left: 4px solid ${color.border}; margin: 20px 0; border-radius: 4px;">
      <tr>
        <td style="padding: 15px; color: ${color.text}; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
          <p style="margin: 0 0 5px 0; font-weight: 600;">${escapedTitle}</p>
          <p style="margin: 0;">${escapedContent}</p>
        </td>
      </tr>
    </table>
  `;
}
