export class AppError extends Error {
  constructor(
    public readonly message: string,
    public readonly code: string,
    public readonly status: number = 400,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export function errBody(message: string, code: string) {
  return { success: false as const, message, code };
}

// ─── Typed error codes ──────────────────────────────────────────────────────
// Central registry for the identity-linking / session / provider error codes
// used across the auth and social-login modules. Kept as plain string
// constants (not a TS enum) so `error.code === ErrorCodes.ACCOUNT_CONFLICT`
// reads the same whether the value came from this codebase or was decoded
// from a JSON response by a consuming client (Furtail app/API, BPA app).
export const ErrorCodes = {
  // A social/provider identity is already linked — either to the
  // currently-authenticated user (no-op) or, when it's linked to a
  // DIFFERENT user, this is the error thrown to prevent silently stealing
  // or merging that identity.
  IDENTITY_ALREADY_LINKED: 'IDENTITY_ALREADY_LINKED',
  // A matching account was found (e.g. by verified email/phone) but the
  // caller must explicitly confirm linking before it proceeds — used to
  // avoid ambiguous auto-merges.
  ACCOUNT_LINK_REQUIRED: 'ACCOUNT_LINK_REQUIRED',
  // Two or more identity signals point at different accounts in a way that
  // cannot be resolved automatically (e.g. provider identity belongs to one
  // user, but the verified email on the incoming profile belongs to a
  // different user). Never resolved by picking one side silently.
  ACCOUNT_CONFLICT: 'ACCOUNT_CONFLICT',
  // The social/identity provider is disabled (globally or, once per-client
  // provider scoping ships, for the requesting client).
  PROVIDER_DISABLED: 'PROVIDER_DISABLED',
  // The provider token/code/profile returned during an OAuth exchange was
  // missing, malformed, or failed verification.
  INVALID_PROVIDER_TOKEN: 'INVALID_PROVIDER_TOKEN',
  // An operation required a verified email but the account/profile's email
  // is unverified (never used to justify a silent account merge).
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  // Same as EMAIL_NOT_VERIFIED but for phone.
  PHONE_NOT_VERIFIED: 'PHONE_NOT_VERIFIED',
  // The LoginSession backing a token/request has been revoked (logout,
  // logout-all, password change, or an admin/security action).
  SESSION_REVOKED: 'SESSION_REVOKED',
  // A refresh token that was already rotated (replaced) was presented
  // again — signals likely token theft; the whole session family is
  // revoked when this is detected.
  REFRESH_TOKEN_REUSED: 'REFRESH_TOKEN_REUSED',
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
