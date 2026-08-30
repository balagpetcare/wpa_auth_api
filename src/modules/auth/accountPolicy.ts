import { UserStatus } from "@prisma/client";

export type AccountAuthenticationState =
  | "missing"
  | "active"
  | "suspended"
  | "deleted";

export function getAccountAuthenticationState(
  status: UserStatus | null | undefined,
): AccountAuthenticationState {
  if (!status) {
    return "missing";
  }

  if (status === UserStatus.SUSPENDED) {
    return "suspended";
  }

  if (status === UserStatus.DELETED) {
    return "deleted";
  }

  return "active";
}

export function canAuthenticateAccount(
  status: UserStatus | null | undefined,
): boolean {
  return getAccountAuthenticationState(status) === "active";
}

export function hasAuthenticatableAccount(
  user: { status: UserStatus } | null | undefined,
): user is { status: UserStatus } {
  return canAuthenticateAccount(user?.status);
}
