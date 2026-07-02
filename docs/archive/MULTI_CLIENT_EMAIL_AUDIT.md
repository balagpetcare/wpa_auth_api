# Multi-Client Email Architecture Audit & Finalization Plan

**Status**: ⚠️ **INCOMPLETE - CRITICAL GAPS IDENTIFIED**  
**Audit Date**: 2026-07-01  
**Priority**: HIGH - Blocks production deployment for multiple clients

---

## Executive Summary

The multi-client email architecture has been **partially implemented** in the schema layer but is **NOT WIRED UP** in the actual email sending flows. The gaps prevent client-specific branding and templates from being used in production.

**Critical Issue**: Auth flows (register, password reset, email verify, login alerts) do NOT pass clientId to email rendering, so all clients get the same global branding regardless of setup.

---

## Current Implementation Status

### ✅ Completed (Schema & Admin Layer)
```
✅ ClientBranding table created
✅ EmailTemplate has clientId field
✅ EmailTemplate has locale field  
✅ Client branding admin endpoints (GET/PATCH)
✅ Database migration ready
✅ Admin UI endpoints for client branding
```

### ⚠️ Incomplete (Email Flow Layer)
```
❌ renderEmailTemplate() doesn't accept clientId parameter
❌ sendTemplatedEmail() doesn't accept clientId parameter
❌ Auth flows don't extract clientId from request/context
❌ Auth flows don't pass clientId to email sending functions
❌ Email mailer doesn't use ClientBranding sender name/email
❌ Template lookup fallback chain not implemented
❌ Email queue doesn't use client-specific sender info
```

### ❓ Unknown (Need Verification)
```
? How does OAuth flow know which client app is making the request?
? Are client apps passed via `client_id` parameter in auth flow?
? Does OAuthClient have a link to AuthClient for email purposes?
```

---

## Current Gaps (5 Critical Issues)

### Gap 1: Email Renderer Doesn't Accept ClientId

**File**: `src/lib/emailRenderer.ts:50-53`

**Current**:
```typescript
export async function renderEmailTemplate(
  templateKey: EmailTemplateKey,
  variables: EmailVariables
): Promise<RenderedEmail>
```

**Problem**: 
- Function doesn't accept `clientId` parameter
- Can't look up client-specific templates
- Can't apply client-specific branding

**Impact**: All emails use global branding only

---

### Gap 2: Template Lookup Chain Not Implemented

**File**: `src/lib/emailRenderer.ts:125-132`

**Current**:
```typescript
const template = await prisma.emailTemplate.findFirst({
  where: { key: templateKey, locale, clientId: clientId || null },
})
```

**Problem**:
- Only tries exact match for (key, locale, clientId)
- No fallback chain
- Returns null if client-specific template not found
- Should implement priority order

**Required Priority Chain**:
```
1. clientId + templateKey + locale
2. clientId + templateKey + en (if locale not found)
3. global + templateKey + locale (clientId = null)
4. global + templateKey + en (fallback locale = en)
5. DEFAULT_EMAIL_TEMPLATES (built-in fallback)
```

**Impact**: If client template missing, uses wrong/global template

---

### Gap 3: Auth Flows Don't Extract ClientId

**File**: `src/modules/auth/auth.service.ts`

**Current**:
- `registerUser()` accepts `clientId` parameter ✅
- But doesn't pass it to email functions ❌

**Example** (Line 151):
```typescript
await sendTemplatedEmailWithFallback({
  templateKey: 'email_verification',
  variables: {...},
  to: opts.email,
  // ❌ NO clientId PASSED
})
```

**Problem**:
- Auth functions receive clientId but ignore it for email
- Each auth endpoint needs to pass clientId through

**Affected Auth Endpoints**:
- `registerUser()` - email verification
- `requestPasswordReset()` - password reset  
- `verifyEmail()` - welcome email
- `loginWithCredentials()` - login alert email
- `loginWithOtp()` - OTP code email
- `acceptAdminInvitation()` - invitation email

**Impact**: Emails always use global branding, never client-specific

---

### Gap 4: Mailer Doesn't Use ClientBranding Sender Info

**File**: `src/lib/mailer.ts`

**Current**:
```typescript
export async function sendEmail(
  to: string,
  subject: string,
  text: string,
  html?: string,
  purpose: OtpTemplatePurpose = 'GENERAL',
) {
  return dispatchEmail({
    to, subject, text, html, purpose,
    // ❌ NO SENDER INFO
  })
}
```

**Problem**:
- Hardcoded sender name/email (from communication provider)
- Doesn't use ClientBranding.senderName/senderEmail
- Client can't customize "From:" line

**Impact**: All emails from same sender, regardless of client

---

### Gap 5: Email Queue Doesn't Apply Client Branding

**File**: `src/services/emailQueueService.ts`

**Current**:
- Queue stores clientId ✅
- But doesn't use it when processing queue

**Problem**:
- Queue processor would need to re-render with client branding
- Current queue just re-sends same HTML/text
- Can't update branding without re-queuing all pending emails

**Impact**: Queued/retried emails won't use client branding even after client branding is set up

---

## Files To Change (Implementation Plan)

### 1. Email Renderer - Core Change
**File**: `src/lib/emailRenderer.ts`
- [ ] Update `renderEmailTemplate()` signature to accept `clientId`
- [ ] Implement template lookup fallback chain (5 levels)
- [ ] Update `getActiveEmailBranding()` to fetch client-specific branding
- [ ] Merge client-specific branding into variables
- [ ] Pass clientId through all helper functions

### 2. Templated Email Sender - Bridge Function
**File**: `src/lib/sendTemplatedEmail.ts`
- [ ] Add `clientId` to `SendTemplatedEmailInput` interface
- [ ] Extract `clientId` from context/request if not provided
- [ ] Pass `clientId` to `renderEmailTemplate()`
- [ ] Pass `clientId` to `dispatchEmail()`

### 3. Mailer - Sender Info Selection
**File**: `src/lib/mailer.ts`
- [ ] Add `clientId` parameter to `sendEmail()`
- [ ] Fetch ClientBranding if clientId provided
- [ ] Use `ClientBranding.senderName` and `ClientBranding.senderEmail`
- [ ] Fallback to global branding sender info
- [ ] Pass sender info to `dispatchEmail()`

### 4. Auth Service - Pass ClientId Through
**File**: `src/modules/auth/auth.service.ts`
- [ ] Extract `clientId` from OAuth/request context
- [ ] Pass `clientId` to all `sendTemplatedEmailWithFallback()` calls
- [ ] Pass `clientId` to `sendLoginAlertEmail()` calls
- [ ] Pass `clientId` to `sendWelcomeEmail()` calls
- [ ] Verify `resolveClient()` is called early to validate client

### 5. Email Notifications - Helper Functions
**File**: `src/lib/emailNotifications.ts`
- [ ] Update `sendLoginAlertEmail(clientId)` signature
- [ ] Update `sendWelcomeEmail(clientId)` signature
- [ ] Pass `clientId` to `sendTemplatedEmail()`

### 6. Communication Service - Dispatch Handler
**File**: `src/modules/communication/communication.service.ts`
- [ ] Update `dispatchEmail()` to accept `clientId`
- [ ] Update `dispatchEmail()` to accept `senderName` and `senderEmail`
- [ ] Use client-specific sender info when sending
- [ ] Store sender info in EmailSendLog for audit

### 7. Admin Routes - Fallback Verification
**File**: `src/modules/email/email.routes.ts`
- [ ] Verify GET `/admin/clients/:clientId/branding` fallback logic
- [ ] Test template lookup chain endpoint (new GET endpoint needed)
- [ ] Add `POST /admin/email-templates/test-lookup` for debugging

### 8. OAuth Login Flow - Client Detection
**File**: `src/modules/oauth/oauth.routes.ts` (if exists)
- [ ] Ensure OAuth routes extract `client_id` from request
- [ ] Pass `clientId` to underlying auth functions
- [ ] Verify client is registered in AuthClient table

---

## Exact Implementation Plan

### Phase 1: Core Email Renderer (2-3 hours)

**Step 1.1**: Update emailRenderer.ts signature
```typescript
export async function renderEmailTemplate(
  templateKey: EmailTemplateKey,
  variables: EmailVariables,
  clientId?: string | null
): Promise<RenderedEmail>
```

**Step 1.2**: Implement getEmailTemplateByKey() fallback chain
```typescript
async function getEmailTemplateByKey(
  templateKey: string,
  locale: string,
  clientId?: string | null
): Promise<EmailTemplateData | null> {
  // Try 1: clientId + key + locale
  let template = await prisma.emailTemplate.findFirst({
    where: { key: templateKey, locale, clientId }
  })
  if (template) return template

  // Try 2: clientId + key + en
  if (locale !== 'en') {
    template = await prisma.emailTemplate.findFirst({
      where: { key: templateKey, locale: 'en', clientId }
    })
    if (template) return template
  }

  // Try 3: global + key + locale
  template = await prisma.emailTemplate.findFirst({
    where: { key: templateKey, locale, clientId: null }
  })
  if (template) return template

  // Try 4: global + key + en
  if (locale !== 'en') {
    template = await prisma.emailTemplate.findFirst({
      where: { key: templateKey, locale: 'en', clientId: null }
    })
    if (template) return template
  }

  // Try 5: DEFAULT_EMAIL_TEMPLATES (in memory)
  const defaultTemplate = DEFAULT_EMAIL_TEMPLATES.find(t => t.key === templateKey)
  return defaultTemplate ? defaultTemplate as any : null
}
```

**Step 1.3**: Implement getClientBranding() with fallback
```typescript
async function getClientBranding(clientId?: string | null): Promise<EmailBrandingData> {
  if (clientId) {
    const clientBranding = await prisma.clientBranding.findUnique({
      where: { clientId }
    })
    if (clientBranding?.isActive) {
      return mergeBranding(clientBranding, DEFAULT_BRANDING)
    }
  }
  
  // Fallback to global branding
  const globalBranding = await getActiveEmailBranding()
  return globalBranding
}
```

**Step 1.4**: Update renderEmailTemplate() to use clientId
```typescript
const [branding, template] = await Promise.all([
  getClientBranding(clientId),
  getEmailTemplateByKey(templateKey, variables.locale || 'en', clientId),
])
```

### Phase 2: Email Sending Functions (1-2 hours)

**Step 2.1**: Update SendTemplatedEmailInput interface
```typescript
interface SendTemplatedEmailInput {
  templateKey: EmailTemplateKey
  variables: EmailVariables
  to: string
  clientId?: string | null  // NEW
  purpose?: OtpTemplatePurpose
  userId?: string | null
  maskSensitiveData?: boolean
}
```

**Step 2.2**: Update sendTemplatedEmail() to pass clientId
```typescript
const rendered = await renderEmailTemplate(
  input.templateKey,
  variables,
  input.clientId  // NEW
)
```

**Step 2.3**: Update sendEmail() signature
```typescript
export async function sendEmail(
  to: string,
  subject: string,
  text: string,
  html?: string,
  purpose: OtpTemplatePurpose = 'GENERAL',
  clientId?: string | null  // NEW
)
```

**Step 2.4**: Pass clientId to dispatchEmail()
```typescript
return dispatchEmail({
  to, subject, text, html, purpose, clientId  // NEW
})
```

### Phase 3: Auth Service Updates (1-2 hours)

**Step 3.1**: Extract clientId from request
```typescript
// In each auth endpoint:
const client = await resolveClient(opts.clientId, req)
const resolvedClientId = client?.id || null
```

**Step 3.2**: Pass clientId to email functions
```typescript
await sendTemplatedEmailWithFallback({
  templateKey: 'email_verification',
  variables: {...},
  to: opts.email,
  clientId: resolvedClientId  // NEW
})
```

**Step 3.3**: Update all affected endpoints:
- registerUser()
- requestPasswordReset()
- verifyEmail()
- loginWithCredentials()
- loginWithOtp()
- acceptAdminInvitation()

### Phase 4: Communication Service (1 hour)

**Step 4.1**: Update dispatchEmail() signature
```typescript
export async function dispatchEmail(input: {
  to: string
  subject: string
  text: string
  html?: string
  purpose?: OtpTemplatePurpose
  clientId?: string | null  // NEW
})
```

**Step 4.2**: Fetch and use client-specific sender
```typescript
let senderName = 'World Pet Association'
let senderEmail = 'noreply@worldpetassociation.org'

if (input.clientId) {
  const clientBranding = await prisma.clientBranding.findUnique({
    where: { clientId: input.clientId }
  })
  if (clientBranding) {
    senderName = clientBranding.senderName || senderName
    senderEmail = clientBranding.senderEmail || senderEmail
  }
}
```

**Step 4.3**: Pass sender info to email provider
```typescript
// Update communication provider call with senderName, senderEmail
const result = await sendViaProvider({
  ...input,
  from: `${senderName} <${senderEmail}>`
})
```

### Phase 5: Testing & Documentation (1-2 hours)

**Step 5.1**: Create test endpoint for template lookup chain
```typescript
GET /admin/email-templates/lookup?templateKey=otp_login&locale=bn&clientId=123
```

**Step 5.2**: Add debug logging to verify chain:
```typescript
console.log(`[EMAIL] Template lookup chain for ${templateKey}:`)
console.log(`  1. Try: clientId=${clientId} + locale=${locale}`)
console.log(`  2. Try: clientId=${clientId} + locale=en`)
console.log(`  3. Try: clientId=null + locale=${locale}`)
console.log(`  4. Try: clientId=null + locale=en`)
console.log(`  5. Try: DEFAULT_EMAIL_TEMPLATES`)
console.log(`  → Found: ${template.key} at level X`)
```

**Step 5.3**: Update documentation
- Template lookup priority chain
- How to create client-specific templates
- How to set up client branding

---

## Configuration for Target Clients

Once implemented, each client can be configured:

### World Pet Association (Global Default)
```
ClientBranding (optional):
- senderName: "World Pet Association"
- senderEmail: "support@worldpetassociation.org"
- logoUrl: https://wpa.org/logo.png
- brandColor: #0f3a7d

EmailTemplates (optional):
- Create custom templates with clientId=wpa.id and locale=en
- Or use global defaults
```

### Bangladesh Pet Association
```
ClientBranding:
- senderName: "বাংলাদেশ পোষা প্রাণী সংস্থা"
- senderEmail: "support@bangladeshpet.org"
- logoUrl: https://bpa.org/logo-bn.png
- brandColor: #ff6c2f

EmailTemplates:
- Create Bengali templates with clientId=bpa.id and locale=bn
- Create English templates with clientId=bpa.id and locale=en
```

### Furtail
```
ClientBranding:
- senderName: "Furtail Support"
- senderEmail: "hello@furtail.app"
- logoUrl: https://furtail.app/logo.png
- brandColor: #9c27b0

EmailTemplates:
- Create custom templates with clientId=furtail.id and locale=en
```

### Future Clients
```
Each new OAuth client (via API):
- Create AuthClient record
- Create ClientBranding record (optional, uses global if not set)
- Create custom EmailTemplates per locale (optional)
- System automatically selects correct branding and template
```

---

## Risk Assessment

### Before Implementation: ⚠️ HIGH RISK
```
❌ Multi-client setup appears complete but doesn't work
❌ Admins may set up client branding that's ignored
❌ All emails look like they're from WPA regardless of client
❌ Support tickets about "wrong branding on email"
```

### After Implementation: ✅ LOW RISK
```
✅ Fallback chain ensures no broken emails
✅ Each client can customize independently
✅ Global defaults work if client doesn't set up branding
✅ Backward compatible - existing code still works
```

---

## Timeline & Effort

| Phase | Task | Hours | Dev | QA |
|-------|------|-------|-----|-----|
| 1 | Email Renderer | 2-3 | 1 | 0.5 |
| 2 | Email Functions | 1-2 | 1 | 0.5 |
| 3 | Auth Service | 1-2 | 2 | 1 |
| 4 | Communication | 1 | 0.5 | 0.5 |
| 5 | Testing | 1-2 | 1 | 2 |
| **TOTAL** | | **6-10** | **5.5** | **4.5** |

**Estimated**: 1-2 day sprint with 2 devs

---

## Verification Checklist

After implementation:

- [ ] Template lookup chain tested with all 5 levels
- [ ] Client-specific templates render correctly
- [ ] Client-specific branding applied to HTML
- [ ] Client-specific sender name/email used in "From" line
- [ ] Fallback to global branding works
- [ ] Auth flows pass clientId through entire chain
- [ ] OAuth login sends client-specific emails
- [ ] Registration sends correct branding per client
- [ ] Password reset uses client branding
- [ ] Queued emails use correct branding on retry
- [ ] No breaking changes to existing single-client setup
- [ ] Logs show which template/branding was selected

---

## Success Criteria

✅ **Implementation Complete When**:

1. Each of 4 target clients can have unique branding
2. Each client can override templates per language
3. Auth flows correctly detect and use client context
4. Email "From:" line matches client configuration
5. Template fallback chain works as specified
6. All existing auth tests pass
7. New multi-client tests added
8. No manual intervention needed to route emails correctly

---

## Dependencies & Notes

### External Dependencies: NONE
- No new libraries needed
- Uses existing Prisma, Express, mailer

### Data Dependencies:
- AuthClient records must be created for each client
- ClientBranding records optional (fallback to global)
- EmailTemplate records optional (fallback to defaults)

### OAuth Client Integration:
- Verify OAuth `client_id` maps to AuthClient.clientId
- If using external OAuth provider, ensure they pass client context through

---

## Recommendation

**Proceed with implementation immediately**. This is a blocking issue for multi-client deployment:

1. **High Impact**: Enables core multi-client use case
2. **Low Risk**: Fallback chain ensures no breakage
3. **Medium Effort**: 1-2 developer days
4. **High Priority**: Blocks production rollout

Without this, all clients get identical branding regardless of configuration.

---

**Report Generated**: 2026-07-01  
**Status**: Ready for implementation  
**Next Step**: Assign developer, create feature branch, start Phase 1
