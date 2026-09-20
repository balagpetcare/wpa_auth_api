export interface JwtIntrospectionPayload {
  readonly sub?: unknown;
  readonly aud?: unknown;
  readonly iss?: unknown;
  readonly exp?: unknown;
  readonly iat?: unknown;
  readonly email?: unknown;
  readonly username?: unknown;
  readonly roles?: unknown;
}

export interface JwtIntrospectionActiveResponse {
  readonly active: true;
  readonly token_type: "Bearer";
  readonly sub: string;
  readonly aud: string | string[];
  readonly exp?: number;
  readonly iat?: number;
  readonly iss: string;
  readonly email?: string | null;
  readonly username?: string | null;
  readonly roles?: string[];
}

export interface JwtIntrospectionInactiveResponse {
  readonly active: false;
}

export type JwtIntrospectionResponse =
  JwtIntrospectionActiveResponse | JwtIntrospectionInactiveResponse;

export function hasExpectedAudience(
  audience: unknown,
  expected: string,
): boolean {
  return typeof audience === "string"
    ? audience === expected
    : Array.isArray(audience) && audience.includes(expected);
}

export function isServiceTokenOwnedByClient(
  tokenClientId: string,
  requestingClientId: string,
): boolean {
  return tokenClientId === requestingClientId;
}

export function buildJwtIntrospectionResponse(
  payload: JwtIntrospectionPayload,
  expectedAudience: string,
  expectedIssuer: string,
  accountIsAuthenticatable: boolean,
  nowSeconds = Math.floor(Date.now() / 1000),
): JwtIntrospectionResponse {
  if (
    !accountIsAuthenticatable ||
    typeof payload.sub !== "string" ||
    payload.sub.length === 0 ||
    !hasExpectedAudience(payload.aud, expectedAudience) ||
    payload.iss !== expectedIssuer
  ) {
    return { active: false };
  }

  if (!Array.isArray(payload.aud) && typeof payload.aud !== "string") {
    return { active: false };
  }

  if (
    payload.exp !== undefined &&
    (typeof payload.exp !== "number" ||
      !Number.isFinite(payload.exp) ||
      payload.exp <= nowSeconds)
  ) {
    return { active: false };
  }

  if (
    payload.iat !== undefined &&
    (typeof payload.iat !== "number" || !Number.isFinite(payload.iat))
  ) {
    return { active: false };
  }

  if (
    (payload.email !== undefined &&
      payload.email !== null &&
      typeof payload.email !== "string") ||
    (payload.username !== undefined &&
      payload.username !== null &&
      typeof payload.username !== "string")
  ) {
    return { active: false };
  }

  if (
    payload.roles !== undefined &&
    (!Array.isArray(payload.roles) ||
      payload.roles.some((role) => typeof role !== "string"))
  ) {
    return { active: false };
  }

  return {
    active: true,
    token_type: "Bearer",
    sub: payload.sub,
    aud: payload.aud,
    exp: typeof payload.exp === "number" ? payload.exp : undefined,
    iat: typeof payload.iat === "number" ? payload.iat : undefined,
    iss: expectedIssuer,
    ...(payload.email !== undefined
      ? { email: payload.email as string | null }
      : {}),
    ...(payload.username !== undefined
      ? { username: payload.username as string | null }
      : {}),
    ...(Array.isArray(payload.roles)
      ? { roles: payload.roles as string[] }
      : {}),
  };
}
