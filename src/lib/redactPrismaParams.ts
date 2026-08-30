/**
 * Redacts Prisma query parameters before they are ever written to a log sink.
 *
 * Prisma serialises bound parameters as a JSON array string, e.g.
 * `["a@b.com","scrypt$1$ab..$cd..",42]`. A maintenance CLI that turned on
 * PRISMA_QUERY_LOG once leaked a bcrypt/scrypt `password_hash` this way. We
 * never need the actual values to diagnose a slow query — the shape is
 * enough — so every element is replaced with a placeholder that keeps only
 * its type and length. Secret-shaped strings (KDF hashes, JWTs, long
 * hex/base64 blobs) are additionally tagged so they are obvious in a log
 * review, but NO raw secret, token, hash, or cookie value is emitted.
 */
export function redactPrismaParams(rawParams: unknown): string {
  let parsed: unknown = rawParams;
  if (typeof rawParams === 'string') {
    try {
      parsed = JSON.parse(rawParams);
    } catch {
      return '[unpar;redacted]';
    }
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  const secretShaped = (s: string) =>
    /^(scrypt|argon2|pbkdf2)\$/i.test(s) ||
    /^\$2[aby]\$/.test(s) ||
    /^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(s) ||
    /^[A-Fa-f0-9]{40,}$/.test(s) ||
    (s.length >= 40 && /^[A-Za-z0-9_-]+$/.test(s));
  const redacted = items.map((v) => {
    if (v === null || v === undefined) return v;
    if (typeof v === 'number' || typeof v === 'boolean') return v;
    if (typeof v === 'string') {
      return secretShaped(v)
        ? `[redacted:secret len=${v.length}]`
        : `[redacted:string len=${v.length}]`;
    }
    return `[redacted:${typeof v}]`;
  });
  return JSON.stringify(redacted);
}
