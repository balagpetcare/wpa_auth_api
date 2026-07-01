/**
 * Default Email Templates
 * These are the factory-default templates that can be restored
 */

export const DEFAULT_EMAIL_TEMPLATES = [
  {
    key: 'otp_login',
    name: 'OTP Login Code',
    subject: 'Your WPA Central Auth Login Code',
    preheader: 'Your one-time code: {{code}}',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .code-box { background: #f0f8ff; border: 2px solid #0f3a7d; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
    .code { font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #0f3a7d; font-family: monospace; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔐 Your Login Code</h1>
    </div>
    <div class="content">
      <p>Enter this code to verify your login to WPA Central Auth:</p>
      <div class="code-box">
        <div class="code">{{code}}</div>
      </div>
      <p style="color: #666; font-size: 14px;">⏰ <strong>This code expires in {{expiresIn}} minutes</strong></p>
      <p style="font-size: 14px;">If you didn't request this code, someone may be trying to access your account. If this wasn't you, please change your password immediately.</p>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy</a> | <a href="{{termsUrl}}">Terms</a> | <a href="{{contactUrl}}">Contact</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Your Login Code

Enter this code to verify your login:

{{code}}

This code expires in {{expiresIn}} minutes.

If you didn't request this code, someone may be trying to access your account. Change your password immediately.

Support: {{supportEmail}}
Help: {{helpUrl}}

© 2024 {{brandName}}. All rights reserved.`,
    variables: {
      required: ['code', 'expiresIn'],
      optional: ['userName', 'brandName', 'supportEmail', 'helpUrl', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
    }
  },
  {
    key: 'email_verification',
    name: 'Email Verification',
    subject: 'Verify Your Email Address for WPA Central Auth',
    preheader: 'Complete your email verification to activate your account',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .action-button { display: inline-block; background: #ff6c2f; color: white; padding: 14px 32px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>✉️ Verify Your Email</h1></div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <p>Thank you for creating your WPA Central Auth account. Click below to verify your email:</p>
      <a href="{{verificationLink}}" class="action-button">Verify Email Address</a>
      <p style="color: #666; font-size: 14px;">⏰ This link expires in {{expiresIn}} hours</p>
    </div>
    <div class="footer">
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a></p>
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Verify Your Email Address\n\nHello {{userName}},\n\nVerify your email: {{verificationLink}}\n\nExpires in {{expiresIn}} hours.\n\n© 2024 {{brandName}}`,
    variables: {
      required: ['verificationLink', 'email', 'expiresIn'],
      optional: ['userName', 'brandName', 'supportEmail', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
    }
  },
  {
    key: 'password_reset',
    name: 'Password Reset Request',
    subject: 'Reset Your WPA Central Auth Password',
    preheader: 'Click to reset your password securely',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .action-button { display: inline-block; background: #ff6c2f; color: white; padding: 14px 32px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>🔑 Password Reset</h1></div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <p>We received a request to reset your password. Click below to create a new password:</p>
      <a href="{{resetPasswordLink}}" class="action-button">Reset Your Password</a>
      <p style="color: #666; font-size: 14px;">⏰ This link expires in {{expiresIn}} hours</p>
    </div>
    <div class="footer">
      <p><a href="{{privacyUrl}}">Privacy</a> | <a href="{{termsUrl}}">Terms</a></p>
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Password Reset Request\n\nHello {{userName}},\n\nReset your password: {{resetPasswordLink}}\n\nExpires in {{expiresIn}} hours.\n\n© 2024 {{brandName}}`,
    variables: {
      required: ['resetPasswordLink', 'expiresIn'],
      optional: ['userName', 'brandName', 'supportEmail', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
    }
  },
  {
    key: 'admin_invitation',
    name: 'Admin Invitation',
    subject: 'You\'re Invited to Join WPA Central Auth Admin Panel',
    preheader: 'Accept your invitation to manage WPA Central Auth',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .action-button { display: inline-block; background: #ff6c2f; color: white; padding: 14px 32px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>🎉 Admin Invitation</h1></div>
    <div class="content">
      <p>Hello,</p>
      <p>You have been invited to join the WPA Central Auth admin panel. Click below to accept:</p>
      <a href="{{inviteLink}}" class="action-button">Accept Invitation</a>
      <p style="color: #666; font-size: 14px;">⏰ This invitation expires in 7 days</p>
    </div>
    <div class="footer">
      <p><a href="{{privacyUrl}}">Privacy</a> | <a href="{{termsUrl}}">Terms</a></p>
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Admin Invitation\n\nYou have been invited to the WPA Central Auth admin panel.\n\nAccept: {{inviteLink}}\n\nExpires in 7 days.\n\n© 2024 {{brandName}}`,
    variables: {
      required: ['inviteLink'],
      optional: ['userName', 'brandName', 'supportEmail', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
    }
  },
  {
    key: 'welcome',
    name: 'Welcome Email',
    subject: 'Welcome to WPA Central Auth',
    preheader: 'Get started with your new account',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>👋 Welcome!</h1></div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <p>Welcome to WPA Central Auth! Your account is now active and ready to use.</p>
      <p>You can now log in at {{websiteUrl}} with your email and password.</p>
    </div>
    <div class="footer">
      <p><a href="{{privacyUrl}}">Privacy</a> | <a href="{{termsUrl}}">Terms</a> | <a href="{{contactUrl}}">Contact</a></p>
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Welcome!\n\nHello {{userName}},\n\nWelcome to WPA Central Auth! Log in at {{websiteUrl}}\n\n© 2024 {{brandName}}`,
    variables: {
      required: [],
      optional: ['userName', 'brandName', 'websiteUrl', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
    }
  },
  {
    key: 'login_alert',
    name: 'Login Alert',
    subject: 'New Login to Your WPA Central Auth Account',
    preheader: 'A new login was detected on your account',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .info-box { background: #f0f8ff; border-left: 4px solid #0f3a7d; padding: 15px; margin: 20px 0; border-radius: 4px; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>🔐 Login Alert</h1></div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <p>A new login to your WPA Central Auth account was detected:</p>
      <div class="info-box">
        <p><strong>IP Address:</strong> {{ipAddress}}</p>
        <p><strong>Time:</strong> {{timestamp}}</p>
        <p><strong>Device:</strong> {{userAgent}}</p>
      </div>
      <p>If this wasn't you, please change your password immediately and contact support.</p>
    </div>
    <div class="footer">
      <p>Support: {{supportEmail}}</p>
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Login Alert\n\nHello {{userName}},\n\nA new login was detected:\nIP: {{ipAddress}}\nTime: {{timestamp}}\nDevice: {{userAgent}}\n\nIf this wasn't you, change your password immediately.\n\n© 2024 {{brandName}}`,
    variables: {
      required: ['ipAddress', 'timestamp', 'userAgent'],
      optional: ['userName', 'brandName', 'supportEmail']
    }
  },
  {
    key: 'password_changed',
    name: 'Password Changed',
    subject: 'Your WPA Central Auth Password Has Been Changed',
    preheader: 'Your password was successfully updated',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .success-box { background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 20px 0; border-radius: 4px; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>✅ Password Changed</h1></div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <div class="success-box">
        <p><strong>✓ Your password has been successfully changed.</strong></p>
      </div>
      <p>Your WPA Central Auth account is now secured with your new password. All active sessions have been ended for your security.</p>
    </div>
    <div class="footer">
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Password Changed\n\nHello {{userName}},\n\nYour password has been successfully changed.\n\nAll active sessions have been ended for your security.\n\n© 2024 {{brandName}}`,
    variables: {
      required: [],
      optional: ['userName', 'brandName']
    }
  },
  {
    key: 'security_alert',
    name: 'Security Alert',
    subject: 'Security Alert: Action Required on Your WPA Central Auth Account',
    preheader: 'Important security notification',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #ff6c2f 0%, #ff8c4d 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .alert-box { background: #fff3cd; border-left: 4px solid #ff6c2f; padding: 15px; margin: 20px 0; border-radius: 4px; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>⚠️ Security Alert</h1></div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <div class="alert-box">
        <p><strong>{{alertType}}</strong></p>
        <p>{{alertDetails}}</p>
      </div>
      <p>Please take immediate action to secure your account. If you did not authorize this activity, change your password and contact support.</p>
    </div>
    <div class="footer">
      <p>Support: {{supportEmail}}</p>
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Security Alert\n\nHello {{userName}},\n\n{{alertType}}\n{{alertDetails}}\n\nPlease change your password and contact support if needed.\n\nSupport: {{supportEmail}}\n\n© 2024 {{brandName}}`,
    variables: {
      required: ['alertType', 'alertDetails'],
      optional: ['userName', 'brandName', 'supportEmail']
    }
  },
  {
    key: 'role_updated',
    name: 'Role Updated',
    subject: 'Your WPA Central Auth Permissions Have Been Updated',
    preheader: 'Your account roles were updated',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .info-box { background: #f0f8ff; border-left: 4px solid #0f3a7d; padding: 15px; margin: 20px 0; border-radius: 4px; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>🔄 Roles Updated</h1></div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <p>Your account roles and permissions have been updated:</p>
      <div class="info-box">
        <p><strong>Changes:</strong></p>
        <p>{{roleChanges}}</p>
      </div>
      <p>If you have questions about these changes, please contact support.</p>
    </div>
    <div class="footer">
      <p>Support: {{supportEmail}}</p>
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Roles Updated\n\nHello {{userName}},\n\nYour account roles and permissions have been updated:\n\n{{roleChanges}}\n\nContact support with questions.\n\n© 2024 {{brandName}}`,
    variables: {
      required: ['roleChanges'],
      optional: ['userName', 'brandName', 'supportEmail']
    }
  },
  {
    key: 'magic_link',
    name: 'Magic Link Login',
    subject: 'Your WPA Central Auth Magic Link',
    preheader: 'Click to sign in without a password',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .action-button { display: inline-block; background: #ff6c2f; color: white; padding: 14px 32px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>🔗 Magic Link</h1></div>
    <div class="content">
      <p>Click below to sign in to your WPA Central Auth account without a password:</p>
      <a href="{{magicLink}}" class="action-button">Sign In Now</a>
      <p style="color: #666; font-size: 14px;">⏰ This link expires in {{expiresIn}} hours</p>
    </div>
    <div class="footer">
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Magic Link\n\nClick to sign in: {{magicLink}}\n\nExpires in {{expiresIn}} hours.\n\n© 2024 {{brandName}}`,
    variables: {
      required: ['magicLink', 'expiresIn'],
      optional: ['brandName']
    }
  },
  {
    key: 'two_factor_code',
    name: 'Two-Factor Code',
    subject: 'Your WPA Central Auth Two-Factor Code',
    preheader: 'Your authentication code: {{code}}',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .code-box { background: #f0f8ff; border: 2px solid #0f3a7d; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
    .code { font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #0f3a7d; font-family: monospace; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>🔐 2FA Code</h1></div>
    <div class="content">
      <p>Enter this code to complete your two-factor authentication:</p>
      <div class="code-box">
        <div class="code">{{code}}</div>
      </div>
      <p style="color: #666; font-size: 14px;">⏰ <strong>This code expires in {{expiresIn}} minutes</strong></p>
      <p style="font-size: 14px;">Never share this code with anyone.</p>
    </div>
    <div class="footer">
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Two-Factor Code\n\nEnter this code to complete authentication:\n\n{{code}}\n\nExpires in {{expiresIn}} minutes.\n\nNever share this code.\n\n© 2024 {{brandName}}`,
    variables: {
      required: ['code', 'expiresIn'],
      optional: ['brandName']
    }
  },
  {
    key: 'account_suspended',
    name: 'Account Suspended',
    subject: 'Your WPA Central Auth Account Has Been Suspended',
    preheader: 'Your account is temporarily suspended',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #ff6c2f 0%, #ff8c4d 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .warning-box { background: #fff3cd; border-left: 4px solid #ff6c2f; padding: 15px; margin: 20px 0; border-radius: 4px; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>🚫 Account Suspended</h1></div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <div class="warning-box">
        <p><strong>Your account has been suspended.</strong></p>
        <p>Reason: {{suspensionReason}}</p>
      </div>
      <p>Please contact support immediately to restore access to your account.</p>
    </div>
    <div class="footer">
      <p>Support: {{supportEmail}}</p>
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Account Suspended\n\nHello {{userName}},\n\nYour account has been suspended.\n\nReason: {{suspensionReason}}\n\nContact support: {{supportEmail}}\n\n© 2024 {{brandName}}`,
    variables: {
      required: ['suspensionReason'],
      optional: ['userName', 'brandName', 'supportEmail']
    }
  },
  {
    key: 'account_reactivated',
    name: 'Account Reactivated',
    subject: 'Your WPA Central Auth Account Has Been Reactivated',
    preheader: 'Your account is now active',
    htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    .success-box { background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 20px 0; border-radius: 4px; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>✅ Account Reactivated</h1></div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <div class="success-box">
        <p><strong>Your WPA Central Auth account has been reactivated.</strong></p>
      </div>
      <p>You can now sign in with your email and password. If you experience any issues, please contact support.</p>
    </div>
    <div class="footer">
      <p>Support: {{supportEmail}}</p>
      <p>© 2024 {{brandName}}</p>
    </div>
  </div>
</body>
</html>`,
    textBody: `Account Reactivated\n\nHello {{userName}},\n\nYour account has been reactivated.\n\nYou can now sign in normally.\n\n© 2024 {{brandName}}`,
    variables: {
      required: [],
      optional: ['userName', 'brandName', 'supportEmail']
    }
  }
]
