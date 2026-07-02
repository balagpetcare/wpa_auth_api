# User Management - Admin Actions

This document details the administrative actions available for managing users within the WPA Central Auth system. The actions have been designed with enterprise safety in mind, preventing accidental lockouts and ensuring all actions are fully auditable.

## Available Actions

1. **View Details**: Opens a read-only profile detailing the user's basic info, verified states, assigned roles, recent login sessions, recent audit logs, and security events.
2. **Suspend / Activate User**: Temporarily disables a user's ability to log in or use active tokens without removing their data.
3. **Reset Password**: Triggers a password reset flow. For security reasons, the raw password is never exposed in the UI.
4. **Force Logout / Revoke Sessions**: Instantly invalidates all active sessions (both web and refresh tokens) across all devices.
5. **Deactivate Account (Soft Delete)**: Permanently disables the account by marking it as `DELETED`.

## Safety Restrictions

To prevent critical system failures or admin lockouts, the following hardcoded safeguards exist in the API layer (`admin.service.ts`):
- **Self-Modification Block**: An admin cannot delete, suspend, or revoke sessions for their own account from the Users list. They must use the `/account` profile page for self-management.
- **Super Admin Protection**: The system explicitly prevents the deletion or suspension of the last remaining user with the `SUPER_ADMIN` role. This guarantees that the system will never be permanently locked out of administrative access.

## Why Soft Delete is Preferred
In an identity and authentication system, "hard deleting" a row from the `users` table introduces severe cascading issues. Historical audit logs, past security events, and related relational data would lose their foreign key integrity. 
Instead, we apply a "Soft Delete" by transitioning the user's status to `DELETED`. This immediately rejects all authentication attempts and revokes tokens, while maintaining the historical footprint required for compliance and security auditing.

## Audit Events Created
Every destructive action strictly writes to the `audit_logs` table:
- `USER_STATUS_CHANGED`: Fired when a user is suspended or activated.
- `USER_ACCOUNT_DELETED`: Fired when a user is deactivated (soft deleted).
- `USER_PASSWORD_RESET_TRIGGERED`: Fired when an admin initiates a password reset.
- `USER_SESSIONS_REVOKED`: Fired when sessions are forcefully revoked.
- `USER_UPDATED`: Fired for general profile changes.

## Required Permissions
*Note: Depending on the specific RBAC implementation, actions should be gated behind:*
- `users.read` for viewing the list and details.
- `users.manage` for general edits.
- `users.suspend` and `users.delete` for destructive actions.
- `users.reset_password` for triggering resets.

## Portal & Floating Positioning for Dropdowns
In complex enterprise tables where the layout uses horizontal overflow (`.table-responsive`), rendering a standard absolute-positioned dropdown menu results in vertical clipping and visibility issues. 
To resolve this:
- We render the Actions dropdown menu inside a React Portal (specifically targeting `document.body`).
- Positioning is computed dynamically on click from the trigger button's `getBoundingClientRect()`.
- Listeners for page scroll and window resize close the active dropdown to prevent visual drift.
- Keyboard listeners close the menu on `Escape`, and document-level click listeners close it on outside click.

## Next.js 16 Dynamic Params Handling
In Next.js 15 and 16 App Router, route parameters (`params` and `searchParams`) inside Server Components are resolved asynchronously as promises rather than plain objects.
- Pages like `/users/[userId]/page.tsx` must type `params` as a promise (e.g., `params: Promise<{ userId: string }>`).
- Before passing any parameter down to Client Components, it must be explicitly awaited: `const { userId } = await params`.
- Accessing parameters synchronously triggers compilation and runtime errors.
