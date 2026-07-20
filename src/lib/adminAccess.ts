import { prisma } from './db.js';

// Global Super Admin, Stage 1 (backend token validation only).
//
// Service-scoped wildcard permissions map 1:1 to dedicated JWT audiences
// that each consuming backend's admin middleware checks for. Kept as an
// explicit allow-list (not derived from the permission string at runtime)
// so a new Permission row can never silently mint a new trusted audience
// without a code change here.
const SERVICE_PERMISSION_TO_ADMIN_AUDIENCE: Record<string, string> = {
  'bpa:*': 'bpa-admin',
  'wpa:*': 'wpa-gateway-admin',
  'furtail:*': 'furtail-admin',
};

export function knownServicePermissions(): string[] {
  return Object.keys(SERVICE_PERMISSION_TO_ADMIN_AUDIENCE);
}

export async function getServiceAdminPermissions(userId: string): Promise<string[]> {
  const rows = await prisma.userRole.findMany({
    where: { userId },
    select: {
      role: {
        select: {
          permissions: {
            select: { permission: { select: { name: true } } },
          },
        },
      },
    },
  });
  const granted = new Set(
    rows.flatMap((row) => row.role.permissions.map((rp) => rp.permission.name)),
  );
  return knownServicePermissions().filter((perm) => granted.has(perm));
}

export function adminAudiencesForPermissions(perms: string[]): string[] {
  return perms
    .map((p) => SERVICE_PERMISSION_TO_ADMIN_AUDIENCE[p])
    .filter((v): v is string => Boolean(v));
}
