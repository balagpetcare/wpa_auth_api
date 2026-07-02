# Multi-Client Email Architecture - Short Audit Summary

**Status**: ⚠️ INCOMPLETE - 5 CRITICAL GAPS  
**Severity**: HIGH - Blocks multi-client deployment  
**Effort**: 1-2 developer days to fix

---

## Current Gaps

### Gap 1: Email Renderer Ignores ClientId
- `renderEmailTemplate()` signature doesn't accept clientId parameter
- Can't load client-specific templates or branding
- **Fix**: Add clientId parameter, implement fallback chain

### Gap 2: No Template Lookup Fallback Chain
- Only tries exact match, returns null if not found
- No priority order for template selection
- **Fix**: Implement 5-level fallback chain (client + locale → global + locale → defaults)

### Gap 3: Auth Flows Don't Pass ClientId
- Auth functions receive clientId but never pass it to email functions
- Affects: register, password reset, verify email, login, OTP, invitations
- **Fix**: Extract clientId from request, pass through entire email chain

### Gap 4: Mailer Doesn't Use ClientBranding Sender Info
- Hardcoded sender name/email from global config
- Client can't customize "From:" line
- **Fix**: Fetch ClientBranding, use senderName/senderEmail if provided

### Gap 5: Email Queue Doesn't Apply Client Branding
- Queue stores clientId but doesn't use it when processing
- Retried emails won't have client branding
- **Fix**: Re-render queued emails with client context before sending

---

## Files To Change (8 files, ~400 lines total code)

| # | File | Change | Lines |
|---|------|--------|-------|
| 1 | `src/lib/emailRenderer.ts` | Add clientId param, implement fallback chain | 80 |
| 2 | `src/lib/sendTemplatedEmail.ts` | Add clientId to interface, pass through | 20 |
| 3 | `src/lib/mailer.ts` | Add clientId param, select sender info | 30 |
| 4 | `src/lib/emailNotifications.ts` | Add clientId to helper functions | 20 |
| 5 | `src/modules/auth/auth.service.ts` | Pass clientId to email functions (6 places) | 30 |
| 6 | `src/modules/oauth/oauth.routes.ts` | Extract client_id from request | 10 |
| 7 | `src/modules/communication/communication.service.ts` | Use ClientBranding sender info | 40 |
| 8 | Tests | Add multi-client email tests | 150 |

---

## Exact Implementation Plan (5 Phases)

### Phase 1: Email Renderer (2-3 hrs)
1. Update `renderEmailTemplate(templateKey, variables, clientId)` signature
2. Implement `getEmailTemplateByKey()` with fallback chain (5 levels)
3. Implement `getClientBranding(clientId)` with fallback to global
4. Merge client-specific branding into template variables

### Phase 2: Email Functions (1-2 hrs)
1. Add `clientId?: string` to `SendTemplatedEmailInput` interface
2. Pass clientId to `renderEmailTemplate()` call
3. Add `clientId` parameter to `sendEmail()` 
4. Pass clientId to `dispatchEmail()`

### Phase 3: Auth Service (1-2 hrs)
1. Extract clientId from request: `const client = await resolveClient(opts.clientId, req)`
2. Pass `clientId` to all 6 email sending calls in:
   - `registerUser()` 
   - `requestPasswordReset()`
   - `verifyEmail()`
   - `loginWithCredentials()`
   - `loginWithOtp()`
   - `acceptAdminInvitation()`

### Phase 4: Communication Service (1 hr)
1. Update `dispatchEmail()` to accept `clientId`
2. Fetch `ClientBranding` if clientId provided
3. Use `ClientBranding.senderName` and `ClientBranding.senderEmail`
4. Pass to email provider in `from` field

### Phase 5: Testing (1-2 hrs)
1. Add test for template lookup fallback chain
2. Test each client gets correct branding
3. Test each client gets correct sender email
4. Verify fallback to global works
5. Verify auth flows work with/without clientId

---

## Template Lookup Priority Chain (Required)

```
FOR email with key="otp_login", locale="bn", clientId="bpa"

PRIORITY ORDER:
1. clientId=bpa + key=otp_login + locale=bn
2. clientId=bpa + key=otp_login + locale=en
3. clientId=null + key=otp_login + locale=bn
4. clientId=null + key=otp_login + locale=en
5. DEFAULT_EMAIL_TEMPLATES[otp_login]

USE FIRST MATCH FOUND
```

---

## Client Configuration Example

### Bangladesh Pet Association Setup
```
1. AuthClient record (already exists)
   - id: "bpa-123"
   - clientId: "bpa-oauth-client"

2. Create ClientBranding
   POST /admin/clients/bpa-123/branding
   {
     "senderName": "বাংলাদেশ পোষা প্রাণী সংস্থা",
     "senderEmail": "support@bangladeshpet.org",
     "logoUrl": "https://bpa.org/logo-bn.png",
     "brandColor": "#ff6c2f"
   }

3. Create Bengali Template (optional)
   POST /admin/email-templates
   {
     "key": "otp_login",
     "locale": "bn",
     "clientId": "bpa-123",
     "name": "OTP লগইন কোড",
     "subject": "আপনার কোড: {{code}}",
     "htmlBody": "...",
     "variables": { "required": ["code"] }
   }

RESULT: All OTP emails for BPA users show BPA branding + Bengali content
```

---

## Before vs After

### BEFORE (Current)
```
All clients → Email with WPA branding
All clients → "From: support@worldpetassociation.org"
All clients → Global English templates only
```

### AFTER (After Implementation)
```
WPA users     → Email with WPA branding (global defaults)
BPA users     → Email with BPA branding + Bengali template
Furtail users → Email with Furtail branding
New clients   → Email with their custom branding (if set up)
              → Falls back to global if not customized
```

---

## Risk Summary

### Current Risk
- ⚠️ Multi-client setup looks complete but doesn't work
- ⚠️ Admins set up client branding that's ignored
- ⚠️ Support issues: "Why is WPA logo on my email?"

### After Implementation
- ✅ Fallback chain ensures no broken emails
- ✅ Each client works independently
- ✅ Backward compatible with existing code
- ✅ All 4 target clients can go live

---

## Effort Estimate

| Phase | Hours | Dev Days |
|-------|-------|----------|
| 1 (Renderer) | 2-3 | 0.5 |
| 2 (Functions) | 1-2 | 0.25 |
| 3 (Auth) | 1-2 | 0.5 |
| 4 (Communication) | 1 | 0.25 |
| 5 (Testing) | 1-2 | 0.5 |
| **TOTAL** | **6-10** | **2** |

**2 Developer Days with 1-2 QA Days for testing**

---

## Dependencies

- ✅ No new libraries
- ✅ No external APIs
- ✅ Database schema already updated
- ✅ Admin UI endpoints already exist
- ⚠️ Need to verify OAuth client_id flow

---

## Next Step

1. Create feature branch: `feature/multi-client-email-finalization`
2. Assign 1-2 developers
3. Start with Phase 1 (Email Renderer)
4. Follow implementation plan
5. Run test suite after each phase
6. Deploy when all phases complete

**Recommendation**: HIGH PRIORITY - Blocks production multi-client rollout
