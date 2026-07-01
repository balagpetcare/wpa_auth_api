/**
 * Email Renderer Usage Examples
 * Demonstrates how to use the email rendering service
 */

import {
  renderEmailTemplate,
  renderOtpCodeBox,
  renderCtaButton,
  renderInfoBlock,
} from './emailRenderer.js';

/**
 * Example 1: Send OTP Login Email
 */
export async function exampleOtpLoginEmail() {
  const variables = {
    code: '123456',
    expiresIn: '10',
    userName: 'John Doe',
  };

  const rendered = await renderEmailTemplate('otp_login', variables);

  console.log('Subject:', rendered.subject);
  console.log('HTML ready:', rendered.html.length > 0);
  console.log('Text ready:', rendered.text.length > 0);

  // Would be passed to sendEmail()
  return rendered;
}

/**
 * Example 2: Send Email Verification
 */
export async function exampleEmailVerification() {
  const variables = {
    verificationLink: 'https://auth.wpa.org/verify?token=abc123def456',
    email: 'user@example.com',
    expiresIn: '24',
  };

  const rendered = await renderEmailTemplate('email_verification', variables);
  return rendered;
}

/**
 * Example 3: Send Password Reset with Error Handling
 */
export async function examplePasswordReset() {
  const variables = {
    resetLink: 'https://auth.wpa.org/reset-password?token=xyz789',
    expiresIn: '1',
  };

  try {
    const rendered = await renderEmailTemplate('password_reset', variables);
    console.log('Password reset email rendered successfully');
    return rendered;
  } catch (error) {
    console.error('Failed to render password reset email:', error);
    throw error;
  }
}

/**
 * Example 4: Send Admin Invitation
 */
export async function exampleAdminInvitation() {
  const variables = {
    acceptLink: 'https://admin.wpa.org/accept-invite?token=invite123',
    inviteeName: 'Jane Smith',
    inviteeEmail: 'jane@example.com',
    expiresAt: '2026-07-15T12:00:00Z',
    inviterName: 'Admin User',
    rolesDisplay: '<span style="background: #0f3a7d; color: white; padding: 4px 8px; border-radius: 3px; margin: 3px;">Admin</span>',
  };

  const rendered = await renderEmailTemplate('admin_invitation', variables);
  return rendered;
}

/**
 * Example 5: Send Two-Factor Code
 */
export async function exampleTwoFactorCode() {
  const variables = {
    code: '987654',
    expiresIn: '300', // seconds
  };

  const rendered = await renderEmailTemplate('two_factor_code', variables);
  return rendered;
}

/**
 * Example 6: Send Security Alert with Multiple Variables
 */
export async function exampleSecurityAlert() {
  const variables = {
    alertType: 'Brute Force Detected',
    detectedAt: new Date().toISOString(),
    alertDescription: 'Multiple failed login attempts detected from IP 192.168.1.1. Your account may be at risk.',
    userName: 'John Doe',
    secureAccountUrl: 'https://admin.wpa.org/security',
  };

  const rendered = await renderEmailTemplate('security_alert', variables);
  return rendered;
}

/**
 * Example 7: Send Login Alert with Location Info
 */
export async function exampleLoginAlert() {
  const variables = {
    loginTime: new Date().toLocaleString(),
    location: 'San Francisco, California, United States',
    ipAddress: '203.0.113.45',
    deviceInfo: 'Chrome 125 on Windows 11',
  };

  const rendered = await renderEmailTemplate('login_alert', variables);
  return rendered;
}

/**
 * Example 8: Render with Minimal Variables (Uses Fallbacks)
 */
export async function exampleMinimalVariables() {
  // Only provide required variables
  const variables = {
    code: '123456',
    expiresIn: '10',
    // Optional variables will use fallbacks from branding
  };

  const rendered = await renderEmailTemplate('otp_login', variables);
  console.log('Rendered with fallback values');
  return rendered;
}

/**
 * Example 9: Error Handling - Missing Required Variables
 */
export async function exampleErrorHandling() {
  const variables = {
    // Missing required 'code' variable
    expiresIn: '10',
  };

  try {
    const rendered = await renderEmailTemplate('two_factor_code', variables);
  } catch (error) {
    // Will throw: Invalid email variables: Missing required variable: code
    console.error('Expected error caught:', error instanceof Error ? error.message : error);
  }
}

/**
 * Example 10: Using Helper Functions for Custom Content
 */
export function exampleUsingHelpers() {
  // These helpers can be used in custom email templates
  const otpBox = renderOtpCodeBox('123456', '5 minutes');
  const button = renderCtaButton('Click Here', 'https://example.com/verify', 'primary');
  const infoBlock = renderInfoBlock('Important Notice', 'This is a test email', 'info');

  console.log('OTP Box HTML:', otpBox);
  console.log('Button HTML:', button);
  console.log('Info Block HTML:', infoBlock);
}

/**
 * Example 11: Batch Email Rendering
 */
export async function exampleBatchRendering() {
  const recipients = [
    {
      email: 'user1@example.com',
      code: '111111',
    },
    {
      email: 'user2@example.com',
      code: '222222',
    },
    {
      email: 'user3@example.com',
      code: '333333',
    },
  ];

  const renderedEmails = [];

  for (const recipient of recipients) {
    const variables = {
      code: recipient.code,
      expiresIn: '10',
    };

    const rendered = await renderEmailTemplate('otp_login', variables);
    renderedEmails.push({
      to: recipient.email,
      ...rendered,
    });
  }

  console.log(`Rendered ${renderedEmails.length} emails`);
  return renderedEmails;
}

/**
 * Example 12: Integration with Email Service
 */
export async function exampleIntegration() {
  const templateKey = 'email_verification';
  const variables = {
    verificationLink: 'https://auth.wpa.org/verify?token=abc123',
    email: 'user@example.com',
    expiresIn: '24',
  };

  // Step 1: Render template
  const rendered = await renderEmailTemplate(templateKey, variables);

  // Step 2: Send email using service (pseudo-code)
  // const result = await sendEmail({
  //   to: 'user@example.com',
  //   subject: rendered.subject,
  //   html: rendered.html,
  //   text: rendered.text,
  // });

  console.log('Email ready to send:', {
    to: 'user@example.com',
    subject: rendered.subject,
  });

  return rendered;
}

/**
 * Example 13: Rendering with Custom Branding Variables
 * (These override database branding if provided)
 */
export async function exampleCustomBranding() {
  const variables = {
    code: '123456',
    expiresIn: '10',
    // Override branding for this email
    brandName: 'Custom Organization Name',
    supportEmail: 'custom-support@example.com',
    websiteUrl: 'https://custom-domain.com',
  };

  const rendered = await renderEmailTemplate('otp_login', variables);
  console.log('Rendered with custom branding');
  return rendered;
}
