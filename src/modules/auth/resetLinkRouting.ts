// Pure, dependency-free routing for auth-email action links (password reset /
// email verification). Factored out of auth.service.ts so it can be unit
// tested without pulling in Prisma/Redis/config. See buildPasswordResetLink /
// buildEmailVerificationLink in auth.service.ts for the config-bound wrappers.

/**
 * Parses a `clientId -> baseUrl` JSON map from an env string. Malformed input
 * must never break the (security-critical) reset flow — it degrades to an
 * empty map so callers fall back to their default URL.
 */
export function parseClientUrlMap(raw: string | undefined | null): Record<string, string> {
  if (!raw || !raw.trim()) return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === 'string' && v.trim()) out[k] = v;
      }
      return out;
    }
  } catch {
    // fall through to empty map
  }
  return {};
}

/** Appends `token=<token>` to a base URL, respecting any existing query. */
export function appendToken(base: string, token: string): string {
  const sep = base.includes('?') ? '&' : '?';
  return `${base}${sep}token=${encodeURIComponent(token)}`;
}

/**
 * Resolves the action link: a per-client base (deep link) when the request
 * carries a known clientId present in `mapRaw`, else the provided default base
 * (e.g. the admin panel URL). Never returns an empty/invalid link.
 */
export function buildActionLink(
  mapRaw: string | undefined | null,
  clientId: string | null | undefined,
  token: string,
  defaultBase: string,
): string {
  const map = parseClientUrlMap(mapRaw);
  const base = clientId ? map[clientId] : undefined;
  if (base) return appendToken(base, token);
  return appendToken(defaultBase, token);
}
