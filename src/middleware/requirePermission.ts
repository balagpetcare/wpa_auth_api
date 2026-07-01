import { Response, NextFunction } from 'express';
import { prisma } from '../lib/db.js';
import { AuthenticatedRequest } from './auth.js';
import { AppError } from '../lib/errors.js';

export function requirePermission(...permissions: string[]) {
  return async (req: AuthenticatedRequest, _res: Response, next: NextFunction) => {
    try {
      if (!req.user?.id) {
        next(new AppError('Unauthorized.', 'UNAUTHORIZED', 401));
        return;
      }

      const userRoles = (req.user.roles ?? []).map((role) => role.toLowerCase());
      if (userRoles.includes('super_admin')) {
        next();
        return;
      }

      const rows = await prisma.userRole.findMany({
        where: { userId: req.user.id },
        select: {
          role: {
            select: {
              permissions: {
                select: {
                  permission: {
                    select: { name: true },
                  },
                },
              },
            },
          },
        },
      });

      const granted = new Set(
        rows.flatMap((row) => row.role.permissions.map((permissionRow) => permissionRow.permission.name.toLowerCase())),
      );

      const allowed = permissions.some((permission) => granted.has(permission.toLowerCase()));
      if (!allowed) {
        next(new AppError('Forbidden: insufficient permissions.', 'FORBIDDEN', 403));
        return;
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}
