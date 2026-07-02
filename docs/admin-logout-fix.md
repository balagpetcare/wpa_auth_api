# Admin Logout Fix

## Root Cause

`POST /api/v1/admin/auth/logout` was wired to the shared logout flow, but the admin UI can call it with no `refreshToken` body.

That path needed to treat `refreshToken` as optional and avoid surfacing a server error when the body is empty or omitted.

## File Changed

- `src/modules/admin/admin.routes.ts`

## Exact Fix

- Added a dedicated logout schema:
  - `refreshToken` is optional and must be a non-empty string if present
- Replaced body middleware for the admin logout route with explicit `safeParse` handling
- If the body is invalid, the route returns `400` with a structured validation response
- If `refreshToken` is present, the existing shared logout service still revokes it
- If `refreshToken` is missing, the shared logout service skips refresh-token invalidation and still revokes the active login session
- Response shape remains:
  - `{ success: true, message: "Logged out successfully" }`

## Verification Results

- `npm run check` passed
- `npx prisma validate` passed
- `npm run build` passed
- Live test passed:
  - `POST /api/v1/admin/auth/logout`
  - Authorization: Bearer token
  - no body
  - returned `200`

## Status

- Logout now works without `refreshToken`
