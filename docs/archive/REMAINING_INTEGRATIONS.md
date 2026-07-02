# Remaining Email Flow Integrations

## Overview
7 of 11 email flows are now **actively integrated**. The remaining 4 flows have service functions ready and are awaiting specific trigger points in your business logic.

## Currently Integrated (7) ✅

1. **Email Verification** - `email_verification` template
2. **Password Reset** - `password_reset` template  
3. **Password Changed Alert** - `password_changed` template
4. **Login Alert** - `login_alert` template
5. **Admin Invitation** - `admin_invitation` template
6. **Welcome** - `welcome` template (NEW - triggered after email verification)
7. **OTP Login** - `otp_login` template (via existing OTP system)

## Ready to Integrate (4)

Service functions are created and ready to use. Just call them from the appropriate handler/endpoint.

### 8. Security Alert Email
**Function:** `sendSecurityAlertEmail(email, userName, alertType, details, userId)`

**When to call:**
- Failed login attempts (brute force detection)
- Suspicious IP address access
- Token reuse detected
- Unauthorized API key usage
- 2FA bypass attempts

**Example integration in `security.service.ts` or similar:**

```typescript
import { sendSecurityAlertEmail } from '../../lib/emailNotifications.js';

// When detecting suspicious activity:
if (failedLoginCount > THRESHOLD) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (user?.email) {
    await sendSecurityAlertEmail(
      user.email,
      user.displayName || user.email,
      'Multiple failed login attempts',
      `${failedLoginCount} failed attempts from IP ${ipAddress}`,
      user.id
    );
  }
}
```

### 9. Role/Permission Update Email
**Function:** `sendRoleUpdatedEmail(email, userName, changes, userId)`

**When to call:**
- In `admin.service.ts` after `assignRoleToUser()` or `removeRoleFromUser()`
- In `admin.service.ts` after updating permissions

**Example integration in `admin.service.ts`:**

```typescript
import { sendRoleUpdatedEmail } from '../../lib/emailNotifications.js';

export async function assignRoleToUser(userId: string, roleId: string, actorId: string, req: Request) {
  // ... existing role assignment logic ...

  const user = await prisma.user.findUnique({ where: { id: userId } });
  const role = await prisma.role.findUnique({ where: { id: roleId } });

  if (user?.email && role) {
    try {
      await sendRoleUpdatedEmail(
        user.email,
        user.displayName || user.email,
        `Assigned role: ${role.name}`,
        user.id
      );
    } catch (e) {
      console.error('Failed to send role update email', e);
    }
  }
}
```

### 10. Magic Link Email
**Function:** `sendMagicLinkEmail(email, magicLink, expiresIn)`

**When to call:**
- Passwordless authentication flow
- Magic link generation for sign-in

**Example integration (new endpoint or in auth flow):**

```typescript
import { sendMagicLinkEmail } from '../../lib/emailNotifications.js';

export async function requestMagicLink(email: string, req: Request) {
  // Generate magic link token
  const token = generateOpaqueToken(32);
  const tokenHash = hashToken(token);
  
  // Store in database
  await prisma.magicLinkToken.create({
    data: {
      email,
      tokenHash,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    },
  });

  const magicLink = `${config.APP_URL}/auth/magic-link?token=${token}`;

  try {
    await sendMagicLinkEmail(email, magicLink, '15 minutes');
  } catch (e) {
    console.error('Failed to send magic link email', e);
  }
}
```

### 11. Two-Factor Code Email
**Function:** `sendTwoFactorCodeEmail(email, code, expiresIn, userId)`

**When to call:**
- After 2FA setup/verification code generation
- User requests new 2FA code
- 2FA challenge during login

**Example integration in 2FA service:**

```typescript
import { sendTwoFactorCodeEmail } from '../../lib/emailNotifications.js';

export async function generateTwoFactorCode(userId: string, email: string) {
  // Generate 6-digit code
  const code = Math.random().toString().slice(2, 8);
  const codeHash = hashToken(code);

  // Store in database
  await prisma.twoFactorCode.create({
    data: {
      userId,
      codeHash,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    },
  });

  try {
    await sendTwoFactorCodeEmail(email, code, '10 minutes', userId);
  } catch (e) {
    console.error('Failed to send 2FA code email', e);
  }

  return { success: true };
}
```

## Additional Integration Opportunities

### Account Suspension/Reactivation
Ready-to-use functions:
- `sendAccountSuspendedEmail(email, userName, reason, userId)`
- `sendAccountReactivatedEmail(email, userName, userId)`

Call these from admin endpoints that suspend/reactivate accounts.

## Implementation Checklist

For each remaining integration:

- [ ] Identify the trigger point (function/endpoint)
- [ ] Import the notification function from `emailNotifications.ts`
- [ ] Add try-catch block (don't fail main operation if email fails)
- [ ] Log errors with `console.error()` for debugging
- [ ] Test with email template (or fallback text)
- [ ] Verify EmailSendLog records are created

## Testing

Once integrated, verify:

```bash
# Check EmailSendLog records were created
SELECT * FROM email_send_logs 
WHERE template_key = 'security_alert'
AND created_at > NOW() - INTERVAL '1 hour';

# Verify masked data
SELECT variables FROM email_send_logs 
WHERE template_key = 'otp_login' LIMIT 1;
-- Should show: {"code": "***123", ...}
```

## Key Design Principles

1. **Non-blocking**: Email failures never interrupt auth/admin flows
2. **Logged**: Every send attempt recorded in EmailSendLog
3. **Masked**: Sensitive data (codes, tokens, links) masked in logs
4. **Fallback**: Missing templates use safe default text
5. **Auditable**: User ID tracked for compliance/debugging

## Template Keys Reference

| Flow | Template Key | Service Function |
|:---|:---|:---|
| Email Verification | `email_verification` | `sendTemplatedEmail()` |
| Password Reset | `password_reset` | `sendTemplatedEmail()` |
| Password Changed | `password_changed` | `sendTemplatedEmail()` |
| Login Alert | `login_alert` | `sendLoginAlertEmail()` |
| Admin Invitation | `admin_invitation` | `sendTemplatedEmail()` |
| Welcome | `welcome` | `sendWelcomeEmail()` |
| OTP Login | `otp_login` | `sendOtpCodeEmail()` |
| Security Alert | `security_alert` | `sendSecurityAlertEmail()` |
| Role Updated | `role_updated` | `sendRoleUpdatedEmail()` |
| Magic Link | `magic_link` | `sendMagicLinkEmail()` |
| Two-Factor Code | `two_factor_code` | `sendTwoFactorCodeEmail()` |

## Next Steps

1. Choose integration points for remaining 4 flows
2. Update relevant service files (admin.service.ts, security.service.ts, etc.)
3. Test email sends with templates
4. Monitor EmailSendLog for failures
5. Create/customize templates in admin panel as needed
