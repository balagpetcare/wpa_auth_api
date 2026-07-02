# Admin Team & Invitation System Documentation

WPA Central Auth provides a secure, enterprise-grade Admin Team Management and Admin Invitation System.

---

## 1. Flows & Architecture

### Flow A: Invite New Admin (New User Setup)
1. **Initiate Invitation:** Admin submits an email address and assigns roles (e.g. `ADMIN` or `SUPER_ADMIN`).
2. **Token Generation:** System generates a secure random token, hashes it using `SHA-256`, and stores only the `tokenHash` in the database.
3. **Invitation Created:** A record is created in the `AdminInvitation` model with a default expiration of **7 days**.
4. **Email Dispatched:** An email containing a secure link is sent:
   `http://localhost:5012/auth/accept-invite?token=<rawToken>`
   *(In local development without SMTP, the admin UI displays the link for copy-pasting).*
5. **Token Verification:** The user visits `/auth/accept-invite`, and the client fetches `/auth/admin-invitations/verify?token=...` to validate status and expiry.
6. **Registration Form:** The user enters their Full Name, Username, and Password.
7. **Accept Invitation:** The backend hashes the token, marks the invitation as `ACCEPTED`, sets `acceptedAt`, creates the `User` with status `ACTIVE`, and assigns the mapped system roles.

### Flow B: Assign Existing Registered User
1. **Search & Select:** Admins search for registered accounts via email or username.
2. **Promote User:** Admin selects the user, assigns roles (e.g. `ADMIN`), and submits.
3. **Role Overwrite:** The backend unlinks existing system roles (`ADMIN`/`SUPER_ADMIN`) and links the new ones, leaving other non-admin client access roles intact.

---

## 2. Token Security & Safeguards

- **No Clear Text Tokens:** Clear text invitation tokens are never logged or stored in the database. The database records only the `SHA-256` token hash.
- **Single-Use Verification:** Once accepted or revoked, the invitation status shifts from `PENDING`, immediately invalidating the token.
- **Expiration Limits:** Default token lifetime is **7 days**. If expired, the link shows a verification error. Admins can resend (extending the expiry window) or revoke the invite.
- **No Secrets in Payloads:** Public endpoints (`verify` and `accept`) return only safe descriptors (email, expiresAt, status) and never expose `tokenHash` or sensitive credential payloads.

---

## 3. Permissions & Role Assignment Safety

- **Super Admin Guard:** Only a `SUPER_ADMIN` can assign or invite another user with the `SUPER_ADMIN` role. This prevents privilege escalation by standard `ADMIN` users.
- **Last Super Admin Safeguard:** The backend counts the total users holding `SUPER_ADMIN` credentials. Demoting, suspending, or deactivating the last remaining `SUPER_ADMIN` user is strictly blocked at the database and service levels, throwing a `403 Forbidden` error.
- **Self-Demotion Guard:** The current admin is prevented from removing their own privileges or revoking their active sessions from the admin UI.

---

## 4. Audit Logs & System Notifications

### Audit Action Events
- `ADMIN_INVITATION_CREATED`: Triggered when an invitation is issued.
- `ADMIN_INVITATION_RESENT`: Triggered when an invitation is renewed or resent.
- `ADMIN_INVITATION_REVOKED`: Triggered when an invitation is cancelled.
- `ADMIN_INVITATION_ACCEPTED`: Triggered when a user accepts the invitation and configures their password.
- `ADMIN_ROLE_ASSIGNED`: Triggered when privileges are assigned or updated.
- `ADMIN_ACCESS_GRANTED`: System notification dispatched to promoted users.

---

## 5. Production Checklist

1. [ ] Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, and `SMTP_PASS` in `.env` to enable live email delivery.
2. [ ] Double check `ADMIN_BASE_URL` in backend `.env` matches the production frontend origin.
3. [ ] Set `NODE_ENV=production` to hide local developer invitation links from the admin panel interface.
4. [ ] Configure rate limiters on `/auth/admin-invitations/accept` and `/auth/admin-invitations/verify` endpoints to prevent token brute force attacks.
