import { prisma } from '../lib/db.js';
import { knownServicePermissions } from '../lib/adminAccess.js';

// Idempotent RBAC bootstrap for the cross-service Global Super Admin role.
//
// Deliberately NOT folded into prisma/seed.ts's `permissionsList`/`rolesList`
// arrays: that seed's step 2b maps every seeded permission onto the existing
// `SUPER_ADMIN` role automatically, which would silently widen any existing
// Central-Auth-only SUPER_ADMIN holder to also carry bpa:*/wpa:*/furtail:*
// service access. GLOBAL_SUPER_ADMIN is introduced as a distinct role so
// existing SUPER_ADMIN accounts are completely unaffected.
export const GLOBAL_SUPER_ADMIN_ROLE = 'GLOBAL_SUPER_ADMIN';

const SERVICE_PERMISSIONS: Array<{ name: string; resource: string; description: string }> = [
  { name: 'bpa:*', resource: 'bpa', description: 'Full administrative access to BPA Admin and BPA Backend API' },
  { name: 'wpa:*', resource: 'wpa', description: 'Full administrative access to WPA Admin, WPA Central Auth, and WPA Gateway' },
  { name: 'furtail:*', resource: 'furtail', description: 'Full administrative access to Furtail Admin and Furtail API' },
];

export async function ensureGlobalSuperAdminRbac(): Promise<{ roleId: string; permissionNames: string[] }> {
  const known = new Set(knownServicePermissions());
  for (const perm of SERVICE_PERMISSIONS) {
    if (!known.has(perm.name)) {
      throw new Error(`Permission ${perm.name} is not in adminAccess.ts's known service-permission map — add it there first.`);
    }
  }

  const role = await prisma.role.upsert({
    where: { name: GLOBAL_SUPER_ADMIN_ROLE },
    update: { description: 'Unified cross-service super admin (BPA, WPA, WPA Gateway, Furtail). See docs/global-super-admin-stage-1.' },
    create: {
      name: GLOBAL_SUPER_ADMIN_ROLE,
      description: 'Unified cross-service super admin (BPA, WPA, WPA Gateway, Furtail). See docs/global-super-admin-stage-1.',
    },
  });

  for (const perm of SERVICE_PERMISSIONS) {
    const permission = await prisma.permission.upsert({
      where: { name: perm.name },
      update: { description: perm.description, resource: perm.resource, action: '*' },
      create: { name: perm.name, description: perm.description, resource: perm.resource, action: '*' },
    });
    await prisma.rolePermission.upsert({
      where: { roleId_permissionId: { roleId: role.id, permissionId: permission.id } },
      update: {},
      create: { roleId: role.id, permissionId: permission.id },
    });
  }

  return { roleId: role.id, permissionNames: SERVICE_PERMISSIONS.map((p) => p.name) };
}
