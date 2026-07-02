/**
 * Email Renderer Types
 * Defines the contract for email template rendering
 */

export type EmailTemplateKey =
  | 'otp_login'
  | 'email_verification'
  | 'password_reset'
  | 'admin_invitation'
  | 'welcome'
  | 'login_alert'
  | 'password_changed'
  | 'security_alert'
  | 'account_suspended'
  | 'account_reactivated'
  | 'role_updated'
  | 'magic_link'
  | 'two_factor_code';

export interface EmailVariables {
  [key: string]: string | number | boolean | undefined | null;
}

export interface RenderEmailTemplateInput {
  templateKey: EmailTemplateKey;
  variables: EmailVariables;
}

export interface RenderedEmail {
  subject: string;
  preheader: string;
  html: string;
  text: string;
}

export interface ResolvedSenderInfo {
  senderName: string;
  senderEmail: string;
  // Phase 2.6A (docs/phase-2-6a-app-aware-communication-routing-ui.md)
  replyTo?: string | null;
}

export interface EmailBrandingData {
  id: string;
  brandName: string;
  logoUrl?: string | null;
  logoAltText?: string | null;
  primaryColor?: string | null;
  textColor?: string | null;
  headerBackgroundColor?: string | null;
  footerBackgroundColor?: string | null;
  supportEmail?: string | null;
  supportPhone?: string | null;
  websiteUrl?: string | null;
  privacyUrl?: string | null;
  termsUrl?: string | null;
  helpUrl?: string | null;
  contactUrl?: string | null;
  footerText?: string | null;
  address?: string | null;
  legalDisclaimer?: string | null;
  // Phase 2.6A (docs/phase-2-6a-app-aware-communication-routing-ui.md)
  replyTo?: string | null;
}

export interface EmailTemplateData {
  id: string;
  key: string;
  name: string;
  subject: string;
  preheader?: string | null;
  htmlBody: string;
  textBody?: string | null;
  variables?: {
    required?: string[];
    optional?: string[];
  } | null;
}

export interface VariableValidationResult {
  isValid: boolean;
  missing: string[];
  errors: string[];
}

export interface LinkButtonOptions {
  text: string;
  href: string;
  variant?: 'primary' | 'danger' | 'secondary';
}

export interface OtpCodeOptions {
  code: string;
  expiresIn?: string | number;
}
